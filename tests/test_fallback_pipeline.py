import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from datetime import datetime
from unittest import mock

from fallback import (
    AuditLogger,
    GitTool,
    ScannerTool,
    cli_approver,
    get_github_mcp_url,
    run_fallback_review,
    select_backend,
)
from fallback.selection import DEFAULT_GITHUB_MCP_URL, force_fallback_enabled, is_mcp_reachable

FAKE_PASSWORD = "Sup3rS3cretFakePw"
FAKE_API_KEY = "sk_test_FAKE1234567890"
ISSUE_URL = "https://github.com/octo/demo/issues/42"
REPO_NAME = "octo/demo"
REAL_RUN = subprocess.run  # captured before any patching so git keeps working


def git(repo, *args):
    return REAL_RUN(
        ["git", "-c", "user.name=T", "-c", "user.email=t@example.com",
         "-c", "commit.gpgsign=false", "-C", repo, *args],
        capture_output=True, text=True, check=True,
    ).stdout.strip()


def make_repo(files):
    """Returns (TemporaryDirectory, sha) for a repo whose second commit adds `files`."""
    tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
    git(tmp.name, "init")
    with open(os.path.join(tmp.name, "readme.txt"), "w") as f:
        f.write("hello\n")
    git(tmp.name, "add", ".")
    git(tmp.name, "commit", "-m", "first")
    for name, content in files.items():
        with open(os.path.join(tmp.name, name), "w") as f:
            f.write(content)
    git(tmp.name, "add", ".")
    git(tmp.name, "commit", "-m", "second")
    return tmp, git(tmp.name, "rev-parse", "HEAD")


class FakeGh:
    """Stands in for `gh`; any other command (git) runs for real."""

    def __init__(self, results=None):
        self.results = list(results) if results is not None else None
        self.calls = []

    def __call__(self, command, *args, **kwargs):
        if command[0] != "gh":
            return REAL_RUN(command, *args, **kwargs)
        self.calls.append({"command": command, "body": (kwargs.get("input") or b"").decode()})
        if self.results is None:
            return gh_result(stdout=ISSUE_URL + "\n")
        outcome = self.results.pop(0) if self.results else gh_result(stdout=ISSUE_URL)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def gh_result(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        args=["gh"], returncode=returncode, stdout=stdout.encode(), stderr=stderr.encode()
    )


SECRET_FILES = {
    "config.py": (
        f'DB_PASSWORD = "{FAKE_PASSWORD}"\n'
        f'API_KEY = "{FAKE_API_KEY}"\n'
        "DEBUG = True\n"
    )
}


@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class FallbackPipelineTests(unittest.TestCase):
    def setUp(self):
        self.repo_dir, self.sha = make_repo(SECRET_FILES)
        self.addCleanup(self.repo_dir.cleanup)
        self.audit_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.audit_dir.cleanup)
        self.audit_path = os.path.join(self.audit_dir.name, "audit.jsonl")

    def run_pipeline(self, approver=None, gh=None, commit_id=None, repo_path=None, **tools):
        approver = approver if approver is not None else mock.Mock(return_value=True)
        gh = gh or FakeGh()
        tools.setdefault("git_tool", GitTool(retry_delay_seconds=0))
        with mock.patch("subprocess.run", gh), self.assertLogs("fallback", level="DEBUG") as logs:
            result = run_fallback_review(
                REPO_NAME,
                repo_path or self.repo_dir.name,
                commit_id or self.sha,
                approver,
                audit=AuditLogger(self.audit_path),
                **tools,
            )
        self.logs = "\n".join(logs.output)
        return result, approver, gh

    def audit_events(self):
        with open(self.audit_path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    def everything(self, result, gh):
        """All text a user, a log reader or an attacker could see."""
        with open(self.audit_path, encoding="utf-8") as f:
            audit_text = f.read()
        return json.dumps(result) + audit_text + self.logs + "".join(c["body"] for c in gh.calls)

    def assert_nothing_sensitive(self, text):
        self.assertNotIn(FAKE_PASSWORD, text)
        self.assertNotIn(FAKE_API_KEY, text)
        self.assertNotIn("diff --git", text)

    # --- success path -----------------------------------------------------
    def test_full_path_git_scanner_approval_issue(self):
        result, approver, gh = self.run_pipeline()

        self.assertTrue(result["success"], result)
        self.assertEqual(set(result), {"success", "summary", "data", "error"})
        self.assertEqual(result["data"]["status"], "ISSUE_CREATED")
        self.assertEqual(result["data"]["issue"], {"issue_number": 42, "issue_url": ISSUE_URL})
        self.assertEqual(result["data"]["approval"], "approved")
        self.assertEqual(result["data"]["risk_level"], "HIGH")
        approver.assert_called_once()
        self.assertEqual(len(gh.calls), 1, "exactly one issue must be created")
        command = gh.calls[0]["command"]
        self.assertEqual(command[:3], ["gh", "issue", "create"])
        self.assertEqual(command[command.index("--repo") + 1], REPO_NAME)

    def test_secrets_are_detected_and_redacted_everywhere(self):
        result, approver, gh = self.run_pipeline()

        findings = result["data"]["findings"]
        self.assertEqual(
            sorted(f["type"] for f in findings),
            ["API_KEY_OR_TOKEN", "HARDCODED_PASSWORD", "UNSAFE_CONFIGURATION"],
        )
        evidence = " ".join(f["evidence"] for f in findings)
        self.assertEqual(evidence.count("[REDACTED]"), 2)
        self.assertEqual({f["file"] for f in findings}, {"config.py"})
        self.assertNotIn("diff", result["data"])
        self.assert_nothing_sensitive(self.everything(result, gh))
        self.assert_nothing_sensitive(json.dumps(approver.call_args.args[0]))
        self.assertIn("[REDACTED]", gh.calls[0]["body"])

    # --- human decision ---------------------------------------------------
    def test_human_no_creates_no_issue(self):
        result, approver, gh = self.run_pipeline(approver=mock.Mock(return_value=False))

        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["status"], "REJECTED")
        self.assertEqual(result["data"]["approval"], "rejected")
        self.assertIsNone(result["data"]["issue"])
        approver.assert_called_once()
        self.assertEqual(gh.calls, [])

    def test_anything_but_an_explicit_yes_is_not_approval(self):
        for name, approver in {
            "string yes": mock.Mock(return_value="yes"),
            "number 1": mock.Mock(return_value=1),
            "None": mock.Mock(return_value=None),
            "raises": mock.Mock(side_effect=RuntimeError(f"password={FAKE_PASSWORD}")),
        }.items():
            with self.subTest(case=name):
                result, _, gh = self.run_pipeline(approver=approver)
                self.assertEqual(result["data"]["status"], "REJECTED")
                self.assertEqual(gh.calls, [])
                self.assert_nothing_sensitive(self.everything(result, gh))

    def test_clean_commit_requests_no_approval_and_creates_no_issue(self):
        clean_repo, clean_sha = make_repo({"app.py": 'import os\nKEY = os.environ["API_KEY"]\n'})
        self.addCleanup(clean_repo.cleanup)

        result, approver, gh = self.run_pipeline(repo_path=clean_repo.name, commit_id=clean_sha)

        self.assertTrue(result["success"])
        self.assertEqual(result["data"]["status"], "CLEAN")
        self.assertEqual(result["data"]["finding_count"], 0)
        approver.assert_not_called()
        self.assertEqual(gh.calls, [])
        self.assertIn("No security issue found", result["summary"])

    # --- failures stop safely --------------------------------------------
    def test_git_failure_stops_safely(self):
        for name, kwargs in {
            "unknown commit": {"commit_id": "deadbeef" * 5},
            "bad repo path": {"repo_path": os.path.join(self.repo_dir.name, "missing")},
        }.items():
            with self.subTest(case=name):
                result, approver, gh = self.run_pipeline(**kwargs)
                self.assertFalse(result["success"])
                self.assertEqual(result["data"]["status"], "FETCH_FAILED")
                self.assertIn(result["error"]["code"], {"INVALID_COMMIT", "INVALID_REPOSITORY"})
                approver.assert_not_called()
                self.assertEqual(gh.calls, [])

    def test_scanner_failure_stops_safely(self):
        result, approver, gh = self.run_pipeline(scanner_tool=ScannerTool(timeout_seconds=-1))

        self.assertFalse(result["success"])
        self.assertEqual(result["data"]["status"], "SCAN_FAILED")
        self.assertEqual(result["error"]["code"], "TIMEOUT")
        approver.assert_not_called()
        self.assertEqual(gh.calls, [])
        self.assert_nothing_sensitive(self.everything(result, gh))

    def test_unexpected_tool_exception_stops_safely_without_leaking(self):
        scanner = mock.Mock()
        scanner.run.side_effect = RuntimeError(f"password={FAKE_PASSWORD} {FAKE_API_KEY}")

        result, approver, gh = self.run_pipeline(scanner_tool=scanner)

        self.assertEqual(result["data"]["status"], "SCAN_FAILED")
        self.assertEqual(result["error"]["code"], "TOOL_CRASHED")
        approver.assert_not_called()
        self.assert_nothing_sensitive(self.everything(result, gh))

    def test_github_cli_failure_returns_safe_error(self):
        stderr = f"HTTP 500: failed password={FAKE_PASSWORD} token: {FAKE_API_KEY}"
        gh = FakeGh([gh_result(returncode=1, stderr=stderr)])

        result, approver, gh = self.run_pipeline(gh=gh)

        self.assertFalse(result["success"])
        self.assertEqual(result["data"]["status"], "ISSUE_FAILED")
        self.assertEqual(result["data"]["approval"], "approved")
        self.assertIsNone(result["data"]["issue"])
        self.assertEqual(result["error"]["code"], "GH_FAILED")
        self.assert_nothing_sensitive(self.everything(result, gh))
        self.assertIn("[REDACTED]", result["error"]["message"])

    def test_issue_creation_is_never_retried_automatically(self):
        failures = [
            subprocess.TimeoutExpired(cmd="gh", timeout=30),
            gh_result(returncode=1, stderr="HTTP 502: bad gateway"),
            gh_result(returncode=1, stderr="authentication required"),
            gh_result(stdout="no url here"),
            FileNotFoundError(),
        ]
        for failure in failures:
            with self.subTest(failure=repr(failure)), mock.patch("time.sleep"):
                result, _, gh = self.run_pipeline(gh=FakeGh([failure]))
                self.assertFalse(result["success"])
                self.assertEqual(len(gh.calls), 1)

    # --- audit trail ------------------------------------------------------
    def test_audit_trail_records_every_step_without_sensitive_data(self):
        result, _, gh = self.run_pipeline()

        events = self.audit_events()
        self.assertEqual(
            [e["action"] for e in events],
            ["workflow_started", "git_show", "security_scan", "diagnosis",
             "human_approval", "create_github_issue", "workflow_completed"],
        )
        self.assertEqual([e["step"] for e in events], list(range(1, 8)))
        self.assertEqual(len({e["run_id"] for e in events}), 1)
        for event in events:
            datetime.fromisoformat(event["timestamp"])
            self.assertTrue(event["tool"] and event["reason"] and event["outcome"])
            self.assertEqual(event["repository"], REPO_NAME)
            self.assertEqual(event["backend"], "fallback")
        self.assertEqual(events[1]["commit_id"], self.sha)
        approval = events[4]
        self.assertEqual(approval["approval_decision"], "approved")
        created = events[5]
        self.assertEqual(created["outcome"], "success")
        self.assertEqual(created["issue_number"], 42)
        self.assertEqual(created["issue_url"], ISSUE_URL)
        self.assertEqual(events[2]["details"]["finding_count"], 3)
        self.assert_nothing_sensitive(self.everything(result, gh))

    def test_audit_records_rejection_and_failures(self):
        self.run_pipeline(approver=mock.Mock(return_value=False))
        rejected = self.audit_events()
        self.assertEqual(rejected[-2]["approval_decision"], "rejected")
        self.assertNotIn("create_github_issue", [e["action"] for e in rejected])

        os.remove(self.audit_path)
        self.run_pipeline(commit_id="deadbeef" * 5)
        failed = self.audit_events()
        self.assertEqual(failed[-2]["action"], "git_show")
        self.assertEqual(failed[-2]["outcome"], "failure")
        self.assertEqual(failed[-2]["error_code"], "INVALID_COMMIT")

    def test_audit_logger_drops_and_redacts_sensitive_values(self):
        audit = AuditLogger(self.audit_path)
        audit.record(
            "x", "tool", f"password={FAKE_PASSWORD}", "success",
            details={
                "diff": "diff --git a/x b/x",
                "evidence": f'API_KEY = "{FAKE_API_KEY}"',
                "password": FAKE_PASSWORD,
                "github_token": "ghp_" + "A" * 30,
                "note": f"key {FAKE_API_KEY} and api_key={FAKE_API_KEY}",
                "count": 3,
            },
        )

        with open(self.audit_path, encoding="utf-8") as f:
            text = f.read()
        self.assert_nothing_sensitive(text)
        self.assertNotIn("ghp_", text)
        self.assertEqual(json.loads(text)["details"]["count"], 3)
        self.assertIn("[REDACTED]", text)

    def test_audit_write_failure_does_not_stop_the_review(self):
        # A directory cannot be opened as a file, so every audit write fails.
        audit = AuditLogger(self.audit_dir.name)

        event = audit.record("x", "tool", "reason", "success")

        self.assertEqual(event["action"], "x")

    def test_audit_path_comes_from_environment_when_not_given(self):
        with mock.patch.dict(os.environ, {"SECURITY_REVIEW_AUDIT_LOG": self.audit_path}):
            AuditLogger().record("x", "tool", "reason", "success")

        self.assertEqual(len(self.audit_events()), 1)


class CliApproverTests(unittest.TestCase):
    def request(self):
        return {"hint": "Approve?"}

    def test_auto_decisions(self):
        with mock.patch("builtins.print"):
            self.assertIs(cli_approver(True)(self.request()), True)
            self.assertIs(cli_approver(False)(self.request()), False)

    def test_interactive_answers(self):
        for answer, expected in {"y": True, "YES": True, "n": False, "": False, "maybe": False}.items():
            with self.subTest(answer=answer), mock.patch("builtins.print"), \
                    mock.patch("builtins.input", return_value=answer):
                self.assertIs(cli_approver(None)(self.request()), expected)


class BackendSelectionTests(unittest.TestCase):
    def test_force_switch_selects_fallback_without_probing(self):
        probe = mock.Mock(return_value=True)

        selection = select_backend(env={"SECURITY_REVIEW_FORCE_FALLBACK": "1"}, probe=probe)

        self.assertEqual(selection["path"], "fallback")
        probe.assert_not_called()

    def test_force_switch_values(self):
        for value, expected in {"1": True, "true": True, "YES": True, "on": True,
                                "0": False, "false": False, "": False}.items():
            with self.subTest(value=value):
                self.assertIs(force_fallback_enabled({"SECURITY_REVIEW_FORCE_FALLBACK": value}), expected)
        self.assertFalse(force_fallback_enabled({}))

    def test_unreachable_mcp_selects_fallback_and_reachable_selects_mcp(self):
        down = select_backend(env={}, probe=lambda url: False)
        up = select_backend(env={}, probe=lambda url: True)

        self.assertEqual((down["path"], up["path"]), ("fallback", "mcp"))
        self.assertIn("unreachable", down["reason"])

    def test_probe_receives_the_overridden_url(self):
        probe = mock.Mock(return_value=True)

        select_backend(env={"GITHUB_MCP_URL": "http://127.0.0.1:9/"}, probe=probe)

        probe.assert_called_once_with("http://127.0.0.1:9/")

    def test_mcp_url_override_and_default(self):
        self.assertEqual(get_github_mcp_url({}), DEFAULT_GITHUB_MCP_URL)
        self.assertEqual(get_github_mcp_url({"GITHUB_MCP_URL": "  "}), DEFAULT_GITHUB_MCP_URL)
        self.assertEqual(get_github_mcp_url({"GITHUB_MCP_URL": "http://x/"}), "http://x/")

    def test_reachability_probe_outcomes(self):
        import urllib.error

        with mock.patch("urllib.request.urlopen") as urlopen:
            self.assertFalse(is_mcp_reachable("file:///etc/passwd"))
            self.assertFalse(is_mcp_reachable("ftp://example.com"))
            urlopen.assert_not_called()
        http_error = urllib.error.HTTPError("http://x", 401, "no", {}, None)
        for side_effect, expected in [
            (http_error, True),
            (urllib.error.URLError("refused"), False),
            (TimeoutError(), False),
        ]:
            with self.subTest(error=repr(side_effect)), \
                    mock.patch("urllib.request.urlopen", side_effect=side_effect):
                self.assertIs(is_mcp_reachable("https://example.com/mcp"), expected)

    def test_dead_address_is_unreachable(self):
        self.assertFalse(is_mcp_reachable("http://127.0.0.1:9/", timeout_seconds=1))


import importlib.util

REQUIRES_MCP = unittest.skipIf(
    importlib.util.find_spec("mcp") is None,
    "the 'mcp' package is not installed (use the project .venv: google-adk[mcp,eval])",
)


@REQUIRES_MCP
class McpUrlOverrideTests(unittest.TestCase):
    def test_both_mcp_toolsets_use_the_overridden_url(self):
        import tools

        with mock.patch.dict(os.environ, {"GITHUB_MCP_URL": "http://127.0.0.1:9/"}), \
                mock.patch("tools.McpToolset") as toolset:
            tools.create_github_readonly_mcp_toolset()
            tools.create_github_write_mcp_toolset()

        urls = [call.kwargs["connection_params"].url for call in toolset.call_args_list]
        self.assertEqual(urls, ["http://127.0.0.1:9/"] * 2)

    def test_default_url_is_unchanged(self):
        import tools

        self.assertEqual(tools.GITHUB_MCP_URL, "https://api.githubcopilot.com/mcp/")


@REQUIRES_MCP
@unittest.skipIf(shutil.which("git") is None, "git is not installed")
class WorkflowWiringTests(unittest.TestCase):
    """Checks that workflow.py picks the right path. MCP/Gemini are never contacted."""

    def setUp(self):
        import workflow

        self.workflow = workflow
        self.repo_dir, self.sha = make_repo(SECRET_FILES)
        self.addCleanup(self.repo_dir.cleanup)
        self.audit_dir = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(self.audit_dir.cleanup)
        self.audit_path = os.path.join(self.audit_dir.name, "audit.jsonl")
        env = mock.patch.dict(
            os.environ,
            {"SECURITY_REVIEW_FORCE_FALLBACK": "1", "SECURITY_REVIEW_AUDIT_LOG": self.audit_path},
        )
        env.start()
        self.addCleanup(env.stop)
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(workflow, "configure_logging").start()
        self.mcp_app = mock.patch.object(
            workflow, "create_security_review_app", side_effect=AssertionError("MCP pipeline built")
        ).start()

    def run_workflow(self, auto_approve, gh):
        with mock.patch("subprocess.run", gh), mock.patch("builtins.print") as printed:
            result = asyncio.run(
                self.workflow.run_security_review_workflow(
                    REPO_NAME, self.sha, auto_approve=auto_approve, repo_path=self.repo_dir.name
                )
            )
        return result, "\n".join(str(c.args[0]) for c in printed.call_args_list if c.args)

    def test_forced_fallback_yes_creates_one_issue_and_skips_mcp_pipeline(self):
        gh = FakeGh()

        result, output = self.run_workflow(True, gh)

        self.assertEqual(result["state"]["fallback_status"], "ISSUE_CREATED")
        self.assertEqual(result["state"]["approval_status"], "approved")
        self.assertEqual(len(gh.calls), 1)
        self.mcp_app.assert_not_called()
        self.assertIn(ISSUE_URL, output)
        for text in (output, json.dumps(result)):
            self.assertNotIn(FAKE_PASSWORD, text)
            self.assertNotIn(FAKE_API_KEY, text)
        with open(self.audit_path, encoding="utf-8") as f:
            events = [json.loads(line) for line in f]
        self.assertEqual(events[0]["action"], "backend_selected")
        self.assertEqual(events[0]["backend"], "fallback")
        self.assertIn("SECURITY_REVIEW_FORCE_FALLBACK", events[0]["reason"])

    def test_forced_fallback_no_creates_no_issue(self):
        gh = FakeGh()

        result, _ = self.run_workflow(False, gh)

        self.assertEqual(result["state"]["fallback_status"], "REJECTED")
        self.assertEqual(gh.calls, [])

    def test_missing_repo_path_stops_safely(self):
        gh = FakeGh()
        with mock.patch.dict(os.environ, {"SECURITY_REVIEW_REPO_PATH": ""}), \
                mock.patch("subprocess.run", gh), mock.patch("builtins.print"):
            result = asyncio.run(
                self.workflow.run_security_review_workflow(REPO_NAME, self.sha, auto_approve=True)
            )

        self.assertEqual(result["state"]["fallback_status"], "FETCH_FAILED")
        self.assertEqual(gh.calls, [])

    def test_mcp_path_is_still_used_when_mcp_is_selected(self):
        mcp = {"path": "mcp", "reason": "GitHub MCP server is reachable"}
        with mock.patch.object(self.workflow, "select_backend", return_value=mcp), \
                mock.patch.object(self.workflow, "run_fallback_review") as fallback:
            with self.assertRaisesRegex(AssertionError, "MCP pipeline built"):
                asyncio.run(
                    self.workflow.run_security_review_workflow(REPO_NAME, self.sha, auto_approve=True)
                )

        fallback.assert_not_called()


if __name__ == "__main__":
    unittest.main()
