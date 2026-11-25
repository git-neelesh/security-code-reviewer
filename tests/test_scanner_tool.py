import json
import os
import shutil
import subprocess
import tempfile
import unittest

from fallback import GitTool, ScannerTool

FAKE_PASSWORD = "Sup3rS3cretFakePw"
FAKE_API_KEY = "sk_test_FAKE1234567890"
FAKE_TOKEN = "ghp_FAKEtoken1234567890abcdefghij"
ALL_FAKE_SECRETS = (FAKE_PASSWORD, FAKE_API_KEY, FAKE_TOKEN)


def make_diff(path, added, start=1):
    """Builds a one-file diff where every line in `added` is a new line."""
    body = "\n".join(f"+{line}" for line in added)
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "index 0000000..b8cd5d1\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +{start},{len(added)} @@\n"
        f"{body}\n"
    )


class ScannerToolTests(unittest.TestCase):
    def setUp(self):
        self.tool = ScannerTool()

    def scan(self, path, *added):
        result = self.tool.run(make_diff(path, list(added)))
        self.assertTrue(result["success"], result)
        return result

    def types(self, result):
        return [f["type"] for f in result["data"]["findings"]]

    def assert_no_secrets(self, result):
        serialized = json.dumps(result)
        for secret in ALL_FAKE_SECRETS:
            self.assertNotIn(secret, serialized)

    def test_result_has_common_contract(self):
        result = self.scan("a.py", 'x = 1')

        self.assertEqual(set(result), {"success", "summary", "data", "error"})
        self.assertIsNone(result["error"])

    def test_detects_hardcoded_passwords(self):
        for name in ("password", "passwd", "pwd", "db_password", "DB_PASSWORD"):
            with self.subTest(name=name):
                result = self.scan("settings.py", f'{name} = "{FAKE_PASSWORD}"')
                finding = result["data"]["findings"][0]
                self.assertEqual(finding["type"], "HARDCODED_PASSWORD")
                self.assertEqual(finding["severity"], "HIGH")
                self.assertEqual(finding["evidence"], f'{name} = "[REDACTED]"')
                self.assert_no_secrets(result)

    def test_detects_api_keys_and_tokens(self):
        for name in ("api_key", "API_TOKEN", "access_token", "secret_key", "github_token", "apiKey"):
            with self.subTest(name=name):
                result = self.scan("client.py", f"{name} = '{FAKE_API_KEY}'")
                finding = result["data"]["findings"][0]
                self.assertEqual(finding["type"], "API_KEY_OR_TOKEN")
                self.assertEqual(finding["severity"], "HIGH")
                self.assertIn("[REDACTED]", finding["evidence"])
                self.assert_no_secrets(result)

    def test_detects_unsafe_configuration_with_severity(self):
        cases = {
            "DEBUG = True": "MEDIUM",
            "debug: true": "MEDIUM",
            "verify_ssl = False": "HIGH",
            "ssl_verify = false": "HIGH",
            "requests.get(url, verify=False)": "HIGH",
        }
        for line, severity in cases.items():
            with self.subTest(line=line):
                result = self.scan("app.py", line)
                self.assertEqual(self.types(result), ["UNSAFE_CONFIGURATION"])
                self.assertEqual(result["data"]["findings"][0]["severity"], severity)

    def test_detects_unquoted_secret_in_config_file_only(self):
        in_env = self.scan(".env", f"DB_PASSWORD={FAKE_PASSWORD}")
        in_yaml = self.scan("config/app.yml", f"api_key: {FAKE_API_KEY}")
        in_code = self.scan("app.py", f"password = {FAKE_PASSWORD}")

        self.assertEqual(self.types(in_env), ["HARDCODED_PASSWORD"])
        self.assertEqual(self.types(in_yaml), ["API_KEY_OR_TOKEN"])
        self.assertEqual(self.types(in_code), [])
        self.assert_no_secrets(in_env)
        self.assert_no_secrets(in_yaml)

    def test_clean_diff_returns_success_with_zero_findings(self):
        result = self.scan("app.py", "def add(a, b):", "    return a + b")

        self.assertEqual(result["data"]["findings"], [])
        self.assertEqual(result["data"]["count"], 0)
        self.assertIn("no security findings", result["summary"])

    def test_environment_variable_configuration_is_not_flagged(self):
        safe_lines = [
            'password = os.environ["DB_PASSWORD"]',
            'API_KEY = os.getenv("API_KEY")',
            'api_key = os.environ.get("API_KEY", "")',
            "const apiKey = process.env.API_KEY;",
            'DEBUG = os.getenv("DEBUG", "false") == "true"',
            'verify_ssl = os.getenv("VERIFY_SSL", "false")',
            'password = ""',
            'password = "${DB_PASSWORD}"',
            "password: ${DB_PASSWORD}",
            'token = "<your-token>"',
            "DEBUG = False",
            "verify_ssl = True",
            "if password == 'x': pass",
        ]
        for line in safe_lines:
            for path in ("app.py", "config.yml"):  # as code and as a config file
                with self.subTest(line=line, path=path):
                    self.assertEqual(self.scan(path, line)["data"]["findings"], [])

    def test_removed_lines_and_diff_metadata_are_ignored(self):
        diff = (
            "diff --git a/db_password=hunter2.env b/db_password=hunter2.env\n"
            "--- a/db_password=hunter2.env\n"
            "+++ b/db_password=hunter2.env\n"
            "@@ -1,3 +1,2 @@\n"
            f'-password = "{FAKE_PASSWORD}"\n'
            f'-DEBUG = True\n'
            ' name = "demo"\n'
            '+password = os.environ["DB_PASSWORD"]\n'
        )

        result = self.tool.run(diff)

        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["findings"], [])
        self.assertEqual(result["data"]["lines_scanned"], 1)
        self.assert_no_secrets(result)

    def test_added_line_that_looks_like_a_header_is_still_scanned(self):
        # Content "++ b/x" becomes the added line "+++ b/x" inside a hunk.
        diff = make_diff("a.py", ['x = "++ b/y"', f'password = "{FAKE_PASSWORD}"'])
        diff = diff.replace('+x = "++ b/y"', "+++ b/a.py")

        result = self.tool.run(diff)

        self.assertEqual(self.types(result), ["HARDCODED_PASSWORD"])
        self.assertEqual(result["data"]["findings"][0]["file"], "a.py")

    def test_file_and_line_numbers_come_from_diff_headers_and_hunks(self):
        diff = (
            "diff --git a/app/one.py b/app/one.py\n"
            "index 111..222 100644\n"
            "--- a/app/one.py\n"
            "+++ b/app/one.py\n"
            "@@ -10,4 +20,5 @@ def f():\n"
            " context line\n"           # new line 20
            "-removed line\n"           # not counted
            '+DEBUG = True\n'           # new line 21
            " context again\n"          # new line 22
            "\\ No newline at end of file\n"
            f'+password = "{FAKE_PASSWORD}"\n'  # new line 23
            "@@ -50,1 +60,2 @@\n"
            " ctx\n"                    # new line 60
            f'+api_key = "{FAKE_API_KEY}"\n'     # new line 61
            "diff --git a/two.py b/two.py\n"
            "--- a/two.py\n"
            "+++ b/two.py\n"
            "@@ -1 +1 @@\n"
            "+verify_ssl = False\n"     # new line 1
        )

        findings = self.tool.run(diff)["data"]["findings"]

        located = [(f["file"], f["line"], f["type"]) for f in findings]
        self.assertEqual(
            located,
            [
                ("app/one.py", 21, "UNSAFE_CONFIGURATION"),
                ("app/one.py", 23, "HARDCODED_PASSWORD"),
                ("app/one.py", 61, "API_KEY_OR_TOKEN"),
                ("two.py", 1, "UNSAFE_CONFIGURATION"),
            ],
        )

    def test_multiple_findings_on_one_line_and_across_lines(self):
        result = self.scan(
            "settings.py",
            f'password = "{FAKE_PASSWORD}"',
            f'api_key = "{FAKE_API_KEY}"; github_token = "{FAKE_TOKEN}"',
            "DEBUG = True",
            "verify_ssl = False",
        )

        findings = result["data"]["findings"]
        self.assertEqual(
            [(f["type"], f["line"]) for f in findings],
            [
                ("HARDCODED_PASSWORD", 1),
                ("API_KEY_OR_TOKEN", 2),
                ("UNSAFE_CONFIGURATION", 3),
                ("UNSAFE_CONFIGURATION", 4),
            ],
        )
        self.assertEqual(result["data"]["count"], 4)
        self.assertIn("4 finding(s)", result["summary"])
        self.assertEqual(findings[1]["evidence"], 'api_key = "[REDACTED]"; github_token = "[REDACTED]"')
        self.assert_no_secrets(result)

    def test_every_finding_has_required_fields(self):
        result = self.scan("a.py", f'password = "{FAKE_PASSWORD}"')

        finding = result["data"]["findings"][0]
        for key in ("type", "rule", "severity", "file", "line", "evidence", "recommendation"):
            self.assertTrue(finding[key], key)

    def test_invalid_and_empty_input_do_not_crash(self):
        for bad in (None, 123, b"bytes", ["list"], {"diff": "x"}):
            with self.subTest(value=bad):
                result = self.tool.run(bad)
                self.assertFalse(result["success"])
                self.assertEqual(result["error"]["code"], "INVALID_INPUT")
                self.assertIsNone(result["data"])

        not_a_diff = self.tool.run("just some text, password = 'abc'")
        self.assertEqual(not_a_diff["error"]["code"], "INVALID_INPUT")
        self.assertNotIn("abc", json.dumps(not_a_diff))

        for empty in ("", "   \n"):
            with self.subTest(value=empty):
                result = self.tool.run(empty)
                self.assertTrue(result["success"])
                self.assertEqual(result["data"]["count"], 0)

    def test_binary_or_mode_only_diff_is_clean(self):
        diff = "diff --git a/logo.png b/logo.png\nBinary files a/logo.png and b/logo.png differ\n"

        result = self.tool.run(diff)

        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["count"], 0)

    def test_very_long_lines_are_skipped_and_counted(self):
        result = self.scan("a.js", "x = '" + "a" * 5000 + "'", f'password = "{FAKE_PASSWORD}"')

        self.assertEqual(result["data"]["skipped_long_lines"], 1)
        self.assertEqual(self.types(result), ["HARDCODED_PASSWORD"])

    def test_timeout_returns_structured_error(self):
        result = ScannerTool(timeout_seconds=-1).run(make_diff("a.py", ["x = 1"]))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "TIMEOUT")

    def test_unexpected_exception_returns_error_without_leaking_secret(self):
        tool = ScannerTool()

        def boom(*args, **kwargs):
            raise ValueError(f"password={FAKE_PASSWORD}")

        tool._scan_added_line = boom
        result = tool.run(make_diff("a.py", [f'password = "{FAKE_PASSWORD}"']))

        self.assertEqual(result["error"]["code"], "SCAN_FAILED")
        self.assert_no_secrets(result)

    def test_secret_is_not_logged(self):
        diff = make_diff(
            "a.py",
            [f'password = "{FAKE_PASSWORD}"', f'api_key = "{FAKE_API_KEY}"', f'x = "{FAKE_TOKEN}"'],
        )

        with self.assertLogs("fallback", level="DEBUG") as logs:
            result = self.tool.run(diff)

        self.assertTrue(result["success"])
        joined = "\n".join(logs.output)
        for secret in ALL_FAKE_SECRETS:
            self.assertNotIn(secret, joined)

    def test_other_known_secret_on_the_same_line_is_also_redacted(self):
        result = self.scan("a.py", f'password = "{FAKE_PASSWORD}"  # old key {FAKE_API_KEY}')

        self.assertIn("[REDACTED]", result["data"]["findings"][0]["evidence"])
        self.assert_no_secrets(result)


@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class ScannerWithGitToolOutputTests(unittest.TestCase):
    def test_scans_the_diff_produced_by_git_tool(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as repo:
            def git(*args):
                return subprocess.run(
                    ["git", "-c", "user.name=T", "-c", "user.email=t@example.com",
                     "-c", "commit.gpgsign=false", "-C", repo, *args],
                    capture_output=True, text=True, check=True,
                ).stdout.strip()

            git("init")
            with open(os.path.join(repo, "readme.txt"), "w") as f:
                f.write("hello\n")
            git("add", ".")
            git("commit", "-m", "first")
            with open(os.path.join(repo, "config.py"), "w") as f:
                f.write(f'import os\nDEBUG = True\nAPI_KEY = "{FAKE_API_KEY}"\n')
            git("add", ".")
            git("commit", "-m", "add config")
            sha = git("rev-parse", "HEAD")

            git_result = GitTool(retry_delay_seconds=0).run(repo, sha)
            self.assertTrue(git_result["success"], git_result)
            result = ScannerTool().run(git_result["data"]["diff"])

        self.assertTrue(result["success"], result)
        located = [(f["file"], f["line"], f["type"]) for f in result["data"]["findings"]]
        self.assertEqual(
            located,
            [("config.py", 2, "UNSAFE_CONFIGURATION"), ("config.py", 3, "API_KEY_OR_TOKEN")],
        )
        self.assertNotIn(FAKE_API_KEY, json.dumps(result))


if __name__ == "__main__":
    unittest.main()
