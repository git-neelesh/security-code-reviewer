import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from fallback import GitTool

FAKE_SECRET = "sk_test_FAKE1234567890"
FAKE_PASSWORD = "hunter2fakepassword"


def _git(repo, *args):
    return subprocess.run(
        [
            "git",
            "-c", "user.name=Test User",
            "-c", "user.email=test@example.com",
            "-c", "commit.gpgsign=false",
            "-C", repo,
            *args,
        ],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["git"], returncode=returncode, stdout=stdout.encode(), stderr=stderr.encode()
    )


MOCK_SHOW_OUTPUT = (
    "commit:" + "a" * 40 + "\n"
    "author:Demo Author\n"
    "date:2026-11-18T07:05:16+05:30\n"
    "message:Add config\n"
    "\n"
    ":000000 100644 0000000 b8cd5d1 A\tconfig.txt\n"
    "\n"
    "diff --git a/config.txt b/config.txt\n"
    "new file mode 100644\n"
    "--- /dev/null\n"
    "+++ b/config.txt\n"
    "@@ -0,0 +1 @@\n"
    f'+API_KEY = "{FAKE_SECRET}"\n'
)


@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class GitToolRealRepositoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.tmp.cleanup)
        self.repo = self.tmp.name
        _git(self.repo, "init")
        with open(os.path.join(self.repo, "readme.txt"), "w") as f:
            f.write("hello\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "first commit")
        with open(os.path.join(self.repo, "config.txt"), "w") as f:
            f.write(f'API_KEY = "{FAKE_SECRET}"\n')
        with open(os.path.join(self.repo, "readme.txt"), "a") as f:
            f.write("more\n")
        _git(self.repo, "add", ".")
        _git(self.repo, "commit", "-m", "add config")
        self.sha = _git(self.repo, "rev-parse", "HEAD")
        self.tool = GitTool(retry_delay_seconds=0)

    def test_valid_commit_returns_diff_and_changed_files(self):
        result = self.tool.run(self.repo, self.sha)

        self.assertTrue(result["success"], result)
        self.assertIsNone(result["error"])
        data = result["data"]
        self.assertEqual(data["commit_id"], self.sha)
        self.assertEqual(data["message"], "add config")
        self.assertEqual(data["author"], "Test User")
        self.assertIn("+++ b/config.txt", data["diff"])
        self.assertIn("API_KEY", data["diff"])
        files = {item["path"]: item["status"] for item in data["changed_files"]}
        self.assertEqual(files, {"config.txt": "A", "readme.txt": "M"})
        self.assertNotIn(FAKE_SECRET, result["summary"])

    def test_short_sha_is_accepted(self):
        result = self.tool.run(self.repo, self.sha[:8])

        self.assertTrue(result["success"], result)
        self.assertEqual(result["data"]["commit_id"], self.sha)

    def test_unknown_commit_returns_structured_error(self):
        result = self.tool.run(self.repo, "deadbeef" * 5)

        self.assertFalse(result["success"])
        self.assertIsNone(result["data"])
        self.assertEqual(result["error"]["code"], "INVALID_COMMIT")
        self.assertEqual(set(result), {"success", "summary", "data", "error"})

    def test_directory_that_is_not_a_repository_returns_structured_error(self):
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as empty_dir:
            result = self.tool.run(empty_dir, self.sha)

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "INVALID_REPOSITORY")

    def test_repository_is_not_modified(self):
        index_path = os.path.join(self.repo, ".git", "index")
        with open(index_path, "rb") as f:
            index_before = f.read()
        status_before = _git(self.repo, "status", "--porcelain")

        self.tool.run(self.repo, self.sha)

        with open(index_path, "rb") as f:
            self.assertEqual(f.read(), index_before)
        self.assertEqual(_git(self.repo, "status", "--porcelain"), status_before)
        self.assertEqual(_git(self.repo, "rev-parse", "HEAD"), self.sha)


class GitToolMockedTests(unittest.TestCase):
    def setUp(self):
        self.tool = GitTool(retry_delay_seconds=0)
        self.repo = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.repo, ignore_errors=True)

    def run_tool(self, side_effect, commit_id="a" * 40):
        with mock.patch("fallback.git_tool.subprocess.run", side_effect=side_effect) as run:
            result = self.tool.run(self.repo, commit_id)
        return result, run

    def test_invalid_commit_format_never_calls_git(self):
        for bad in ("", "--output=evil", "HEAD", "abc", "g" * 40, "a" * 65, None):
            with self.subTest(commit_id=bad):
                result, run = self.run_tool([], commit_id=bad)
                self.assertEqual(result["error"]["code"], "INVALID_COMMIT")
                run.assert_not_called()

    def test_invalid_repository_path_never_calls_git(self):
        for bad in ("", "   ", os.path.join(self.repo, "missing"), None, 123):
            with self.subTest(repository=bad):
                with mock.patch("fallback.git_tool.subprocess.run") as run:
                    result = self.tool.run(bad, "a" * 40)
                self.assertEqual(result["error"]["code"], "INVALID_REPOSITORY")
                run.assert_not_called()

    def test_timeout_is_retried_once_then_succeeds(self):
        result, run = self.run_tool(
            [subprocess.TimeoutExpired(cmd="git", timeout=1), _completed(stdout=MOCK_SHOW_OUTPUT)]
        )

        self.assertTrue(result["success"], result)
        self.assertEqual(run.call_count, 2)

    def test_repeated_timeout_returns_structured_error_after_one_retry(self):
        result, run = self.run_tool(subprocess.TimeoutExpired(cmd="git", timeout=1))

        self.assertFalse(result["success"])
        self.assertEqual(result["error"]["code"], "TIMEOUT")
        self.assertEqual(run.call_count, 2)

    def test_git_missing_is_not_retried(self):
        result, run = self.run_tool(FileNotFoundError())

        self.assertEqual(result["error"]["code"], "GIT_NOT_FOUND")
        self.assertEqual(run.call_count, 1)

    def test_unrecoverable_git_failure_is_not_retried(self):
        result, run = self.run_tool([_completed(returncode=128, stderr="fatal: something odd")])

        self.assertEqual(result["error"]["code"], "GIT_FAILED")
        self.assertEqual(run.call_count, 1)

    def test_bad_revision_maps_to_invalid_commit_without_retry(self):
        result, run = self.run_tool(
            [_completed(returncode=128, stderr="fatal: bad revision 'x^{commit}'")]
        )

        self.assertEqual(result["error"]["code"], "INVALID_COMMIT")
        self.assertEqual(run.call_count, 1)

    def test_lock_failure_is_retried_once(self):
        lock_error = _completed(returncode=128, stderr="fatal: Unable to create 'x/index.lock'")
        result, run = self.run_tool([lock_error, lock_error])

        self.assertEqual(result["error"]["code"], "GIT_FAILED")
        self.assertEqual(run.call_count, 2)

    def test_only_read_only_show_command_is_used_without_shell(self):
        _, run = self.run_tool([_completed(stdout=MOCK_SHOW_OUTPUT)])

        command = run.call_args.args[0]
        self.assertIn("show", command)
        for forbidden in ("commit", "checkout", "reset", "clean", "push", "fetch", "add", "rm"):
            self.assertNotIn(forbidden, command)
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertIsNotNone(run.call_args.kwargs["timeout"])

    def test_errors_do_not_contain_secrets(self):
        stderr = f"fatal: password={FAKE_PASSWORD} token: {FAKE_SECRET}"
        result, _ = self.run_tool([_completed(returncode=1, stderr=stderr)])

        serialized = repr(result)
        self.assertNotIn(FAKE_PASSWORD, serialized)
        self.assertNotIn(FAKE_SECRET, serialized)
        self.assertIn("[REDACTED]", result["error"]["message"])

    def test_logs_do_not_contain_secrets(self):
        with self.assertLogs("fallback", level="DEBUG") as logs:
            success, _ = self.run_tool([_completed(stdout=MOCK_SHOW_OUTPUT)])
            self.run_tool([_completed(returncode=1, stderr=f"password={FAKE_PASSWORD}")])

        self.assertTrue(success["success"])
        self.assertIn(FAKE_SECRET, success["data"]["diff"])
        joined = "\n".join(logs.output)
        self.assertNotIn(FAKE_SECRET, joined)
        self.assertNotIn(FAKE_PASSWORD, joined)
        self.assertNotIn(FAKE_SECRET, success["summary"])

    def test_diff_is_truncated_when_over_limit(self):
        self.tool = GitTool(retry_delay_seconds=0, max_diff_chars=20)
        result, _ = self.run_tool([_completed(stdout=MOCK_SHOW_OUTPUT)])

        self.assertTrue(result["data"]["truncated"])
        self.assertEqual(len(result["data"]["diff"]), 20)


if __name__ == "__main__":
    unittest.main()
