import json
import subprocess
import unittest
from unittest import mock

from fallback import GitHubIssueTool, ScannerTool, compute_approval_token

FAKE_PASSWORD = "Sup3rS3cretFakePw"
FAKE_API_KEY = "sk_test_FAKE1234567890"
ISSUE_URL = "https://github.com/octo/demo/issues/42"

FINDINGS = [
    {
        "type": "API_KEY_OR_TOKEN",
        "severity": "HIGH",
        "file": "config.py",
        "line": 3,
        "evidence": 'API_KEY = "[REDACTED]"',
        "recommendation": "Load the key from an environment variable.",
    },
    {
        "type": "UNSAFE_CONFIGURATION",
        "severity": "MEDIUM",
        "file": "app.py",
        "line": 7,
        "evidence": "DEBUG = True",
        "recommendation": "Disable debug mode in production.",
    },
]
REPO = "octo/demo"
COMMIT = "f877d0d0eb13eaafd4cc6c37c1db72481a8f82a7"
TITLE = "[Security] HIGH: 2 finding(s) in commit f877d0d"


def make_payload(**overrides):
    payload = {"repository": REPO, "commit_id": COMMIT, "title": TITLE, "findings": [dict(f) for f in FINDINGS]}
    payload.update(overrides)
    if "approval" not in overrides:
        token = compute_approval_token(
            payload["repository"], payload["commit_id"], payload["title"], payload["findings"]
        )
        payload["approval"] = {"status": "approved", "token": token}
    return payload


def completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["gh"], returncode=returncode, stdout=stdout.encode(), stderr=stderr.encode()
    )


class GitHubIssueToolTests(unittest.TestCase):
    def setUp(self):
        self.tool = GitHubIssueTool()

    def run_tool(self, payload, side_effect=None):
        if side_effect is None:
            side_effect = [completed(stdout=ISSUE_URL + "\n")]
        with mock.patch("fallback.github_issue_tool.subprocess.run", side_effect=side_effect) as run:
            result = self.tool.run(payload)
        return result, run

    def test_approved_payload_creates_issue_and_returns_url_and_number(self):
        result, run = self.run_tool(make_payload())

        self.assertTrue(result["success"], result)
        self.assertEqual(set(result), {"success", "summary", "data", "error"})
        self.assertIsNone(result["error"])
        self.assertEqual(result["data"]["issue_url"], ISSUE_URL)
        self.assertEqual(result["data"]["issue_number"], 42)
        self.assertIn("#42", result["summary"])
        run.assert_called_once()

    def test_gh_is_called_with_expected_repository_title_and_body(self):
        _, run = self.run_tool(make_payload())

        command = run.call_args.args[0]
        self.assertEqual(command[:3], ["gh", "issue", "create"])
        self.assertEqual(command[command.index("--repo") + 1], REPO)
        self.assertEqual(command[command.index("--title") + 1], TITLE)
        self.assertEqual(command[command.index("--body-file") + 1], "-")
        body = run.call_args.kwargs["input"].decode()
        for expected in (
            "API_KEY_OR_TOKEN", "HIGH", "`config.py`", "**Line:** 3", 'API_KEY = "[REDACTED]"',
            "Load the key from an environment variable.", "UNSAFE_CONFIGURATION", "DEBUG = True",
            COMMIT,
        ):
            self.assertIn(expected, body)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(run.call_args.kwargs["timeout"], self.tool.timeout_seconds)

    def test_missing_or_rejected_approval_blocks_creation(self):
        base = make_payload()
        good_token = base["approval"]["token"]
        blocked = {
            "no approval key": {k: v for k, v in base.items() if k != "approval"},
            "approval is None": make_payload(approval=None),
            "approval is True": make_payload(approval=True),
            "pending": make_payload(approval={"status": "pending", "token": good_token}),
            "rejected": make_payload(approval={"status": "rejected", "token": good_token}),
            "empty status": make_payload(approval={"status": "", "token": good_token}),
            "missing token": make_payload(approval={"status": "approved"}),
            "blank token": make_payload(approval={"status": "approved", "token": "  "}),
        }
        for name, payload in blocked.items():
            with self.subTest(case=name):
                result, run = self.run_tool(payload)
                self.assertFalse(result["success"])
                self.assertEqual(result["error"]["code"], "NOT_APPROVED")
                run.assert_not_called()

    def test_invalid_token_or_changed_content_blocks_creation(self):
        tampered_title = make_payload()
        tampered_title["title"] = "[Security] something else"
        tampered_findings = make_payload()
        tampered_findings["findings"][0]["evidence"] = "API_KEY = [REDACTED]"
        cases = {
            "wrong token": make_payload(approval={"status": "approved", "token": "abc123"}),
            "title changed": tampered_title,
            "findings changed": tampered_findings,
            "other repo": {**make_payload(), "repository": "octo/other"},
        }
        for name, payload in cases.items():
            with self.subTest(case=name):
                result, run = self.run_tool(payload)
                self.assertEqual(result["error"]["code"], "INVALID_APPROVAL_TOKEN")
                run.assert_not_called()

    def test_invalid_payloads_return_structured_errors(self):
        bad_payloads = {
            "None": None,
            "empty dict": {},
            "list": [],
            "missing repository": make_payload(repository=None),
            "bad repository": make_payload(repository="not-a-repo"),
            "repository with option": make_payload(repository="--repo/x"),
            "bad commit": make_payload(commit_id="HEAD"),
            "empty title": make_payload(title="  "),
            "long title": make_payload(title="x" * 300),
            "no findings": make_payload(findings=[]),
            "findings not a list": make_payload(findings="oops"),
            "finding missing evidence": make_payload(findings=[{**FINDINGS[0], "evidence": ""}]),
            "unknown severity": make_payload(findings=[{**FINDINGS[0], "severity": "SCARY"}]),
            "bad line": make_payload(findings=[{**FINDINGS[0], "line": "3"}]),
        }
        for name, payload in bad_payloads.items():
            with self.subTest(case=name):
                result, run = self.run_tool(payload)
                self.assertFalse(result["success"])
                self.assertIn(result["error"]["code"], {"INVALID_PAYLOAD", "NOT_APPROVED"})
                self.assertIsNone(result["data"])
                run.assert_not_called()

    def test_scanner_output_is_accepted_as_findings(self):
        diff = (
            "diff --git a/config.py b/config.py\n--- /dev/null\n+++ b/config.py\n"
            f'@@ -0,0 +1,2 @@\n+DEBUG = True\n+API_KEY = "{FAKE_API_KEY}"\n'
        )
        findings = ScannerTool().run(diff)["data"]["findings"]
        payload = make_payload(findings=findings)

        result, run = self.run_tool(payload)

        self.assertTrue(result["success"], result)
        self.assertNotIn(FAKE_API_KEY, run.call_args.kwargs["input"].decode())

    def test_unredacted_secret_blocks_creation_and_is_not_echoed(self):
        leaky = [{**FINDINGS[0], "evidence": f'API_KEY = "{FAKE_API_KEY}"'}]
        leaky_title = f"[Security] password={FAKE_PASSWORD} leaked"
        for name, payload in {
            "evidence": make_payload(findings=leaky),
            "title": make_payload(title=leaky_title),
            "recommendation": make_payload(
                findings=[{**FINDINGS[0], "recommendation": f"rotate password: {FAKE_PASSWORD}"}]
            ),
        }.items():
            with self.subTest(field=name):
                result, run = self.run_tool(payload)
                self.assertEqual(result["error"]["code"], "UNREDACTED_SECRET")
                run.assert_not_called()
                serialized = json.dumps(result)
                self.assertNotIn(FAKE_API_KEY, serialized)
                self.assertNotIn(FAKE_PASSWORD, serialized)

    def test_cli_failures_return_structured_errors(self):
        cases = {
            "GH_AUTH_FAILED": "To get started with GitHub CLI, please run:  gh auth login",
            "REPOSITORY_NOT_FOUND": "GraphQL: Could not resolve to a Repository with the name 'octo/demo'.",
            "GH_FAILED": "something unexpected happened",
        }
        for code, stderr in cases.items():
            with self.subTest(code=code):
                result, run = self.run_tool(make_payload(), [completed(returncode=1, stderr=stderr)])
                self.assertFalse(result["success"])
                self.assertIsNone(result["data"])
                self.assertEqual(result["error"]["code"], code)
                run.assert_called_once()

    def test_gh_not_installed_returns_structured_error(self):
        result, run = self.run_tool(make_payload(), FileNotFoundError())

        self.assertEqual(result["error"]["code"], "GH_NOT_FOUND")
        run.assert_called_once()

    def test_success_exit_without_issue_url_is_not_reported_as_success(self):
        result, _ = self.run_tool(make_payload(), [completed(stdout="done\n")])

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "UNVERIFIED_RESULT")
        self.assertIn("check the repository", result["error"]["message"])

    def test_timeout_is_handled_safely(self):
        result, run = self.run_tool(make_payload(), subprocess.TimeoutExpired(cmd="gh", timeout=30))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "TIMEOUT")
        self.assertIn("may or may not", result["error"]["message"])
        run.assert_called_once()

    def test_no_automatic_retry_for_any_failure(self):
        failures = [
            subprocess.TimeoutExpired(cmd="gh", timeout=30),
            [completed(returncode=1, stderr="HTTP 502: bad gateway")],
            [completed(returncode=1, stderr="authentication required")],
            [completed(stdout="no url")],
            OSError("boom"),
        ]
        for side_effect in failures:
            with self.subTest(failure=repr(side_effect)):
                with mock.patch("time.sleep") as sleep:
                    result, run = self.run_tool(make_payload(), side_effect)
                self.assertFalse(result["success"])
                self.assertEqual(run.call_count, 1)
                sleep.assert_not_called()

    def test_unexpected_exception_returns_error_without_leaking_secret(self):
        tool = GitHubIssueTool()
        with mock.patch.object(tool, "_build_body", side_effect=ValueError(f"password={FAKE_PASSWORD}")):
            result = tool.run(make_payload())

        self.assertEqual(result["error"]["code"], "ISSUE_TOOL_FAILED")
        self.assertNotIn(FAKE_PASSWORD, json.dumps(result))

    def test_secrets_never_appear_in_body_result_error_or_logs(self):
        # A secret echoed by gh on stderr must be redacted in the returned error.
        stderr = f"failed: password={FAKE_PASSWORD} token: {FAKE_API_KEY}"
        with self.assertLogs("fallback", level="DEBUG") as logs:
            success, run_ok = self.run_tool(make_payload())
            failure, _ = self.run_tool(make_payload(), [completed(returncode=1, stderr=stderr)])
            self.run_tool(make_payload(findings=[{**FINDINGS[0], "evidence": f'k = "{FAKE_API_KEY}"'}]))

        everything = json.dumps([success, failure]) + run_ok.call_args.kwargs["input"].decode()
        everything += "\n".join(logs.output)
        self.assertNotIn(FAKE_PASSWORD, everything)
        self.assertNotIn(FAKE_API_KEY, everything)
        self.assertIn("[REDACTED]", failure["error"]["message"])
        self.assertTrue(success["success"])


if __name__ == "__main__":
    unittest.main()
