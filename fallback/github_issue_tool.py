"""GitHubIssueTool: creates one GitHub issue with `gh issue create`, only after human approval."""

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
from typing import Any, Optional

from fallback.result import fail, ok, redact_text

logger = logging.getLogger(__name__)

_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]*/[A-Za-z0-9_.][A-Za-z0-9_.-]*$")
_COMMIT_PATTERN = re.compile(r"^[0-9a-fA-F]{4,64}$")
_TYPE_PATTERN = re.compile(r"^[A-Z0-9_]{1,50}$")
_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_ISSUE_URL_PATTERN = re.compile(r"https://[^\s/]+/[^\s/]+/[^\s/]+/issues/(\d+)")
_AUTH_MARKERS = ("gh auth login", "not logged in", "authentication", "bad credentials", "http 401")
_NOT_FOUND_MARKERS = ("could not resolve to a repository", "http 404", "not found")

MAX_TITLE_CHARS = 256
MAX_FINDINGS = 50
MAX_FIELD_CHARS = 500


def compute_approval_token(repository: str, commit_id: str, title: str, findings: list) -> str:
    """Returns the token that proves this exact content was shown to and approved by a human.

    The caller creates it only after the human approves (for example when the existing
    request_security_issue_approval tool reports status "approved"). If the repository,
    commit, title or findings change afterwards, the token no longer matches and
    GitHubIssueTool refuses to create the issue. It is an integrity check, not a login.
    """
    canonical = json.dumps(
        {"repository": repository, "commit_id": commit_id, "title": title, "findings": findings},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class GitHubIssueTool:
    """Creates a GitHub issue from approved, already-redacted findings. Never retries."""

    def __init__(self, timeout_seconds: float = 30.0, gh_executable: str = "gh") -> None:
        self.timeout_seconds = timeout_seconds
        self.gh_executable = gh_executable

    def run(self, approved_payload: dict) -> dict:
        """Creates the issue and returns {"success", "summary", "data", "error"}.

        approved_payload = {
            "repository": "owner/repo",
            "commit_id": "<sha>",
            "title": "[Security] HIGH: ...",
            "findings": [{type, severity, file, line, evidence, recommendation}, ...],
            "approval": {"status": "approved", "token": compute_approval_token(...)},
        }
        On success `data` is {"issue_url", "issue_number", "repository"}.
        """
        try:
            return self._run(approved_payload)
        except Exception as exc:  # never include exc text: it could contain payload content
            return fail(
                "ISSUE_TOOL_FAILED",
                f"Unexpected error while creating the issue: {type(exc).__name__}.",
                "Issue creation failed.",
            )

    def _run(self, payload: Any) -> dict:
        if not isinstance(payload, dict) or not payload:
            return self._invalid("Payload must be a non-empty dictionary.")

        # Approval comes first so an unapproved request is never processed further.
        approval = payload.get("approval")
        token = approval.get("token") if isinstance(approval, dict) else None
        status = approval.get("status") if isinstance(approval, dict) else None
        if (
            not isinstance(status, str)
            or status.strip().casefold() != "approved"
            or not isinstance(token, str)
            or not token.strip()
        ):
            return fail(
                "NOT_APPROVED",
                "Human approval is missing, not approved, or has no approval token. No issue was created.",
                "Issue creation blocked: no human approval.",
            )

        repository = payload.get("repository")
        if not isinstance(repository, str) or not _REPOSITORY_PATTERN.fullmatch(repository.strip()):
            return self._invalid("Repository must be in 'owner/repo' format.")
        repository = repository.strip()

        commit_id = payload.get("commit_id")
        if not isinstance(commit_id, str) or not _COMMIT_PATTERN.fullmatch(commit_id.strip()):
            return self._invalid("Commit ID must be a 4-64 character hexadecimal SHA.")
        commit_id = commit_id.strip()

        title = payload.get("title")
        if not isinstance(title, str) or not " ".join(title.split()):
            return self._invalid("Title must be a non-empty string.")
        title = " ".join(title.split())
        if len(title) > MAX_TITLE_CHARS:
            return self._invalid(f"Title must be at most {MAX_TITLE_CHARS} characters.")

        raw_findings = payload.get("findings")
        findings = self._clean_findings(raw_findings)
        if findings is None:
            return self._invalid(
                f"Findings must be a list of 1-{MAX_FINDINGS} items, each with type, severity, "
                "file, evidence and recommendation."
            )

        expected = compute_approval_token(repository, commit_id, payload["title"], raw_findings)
        if not hmac.compare_digest(token.strip(), expected):
            return fail(
                "INVALID_APPROVAL_TOKEN",
                "Approval token does not match the submitted issue content. No issue was created.",
                "Issue creation blocked: invalid approval token.",
            )

        # Verify instead of trusting that the content is already redacted.
        texts = [title] + [f[key] for f in findings for key in ("file", "evidence", "recommendation")]
        if any(redact_text(text) != text for text in texts):
            return fail(
                "UNREDACTED_SECRET",
                "Payload appears to contain an unredacted secret. Replace it with [REDACTED]. "
                "No issue was created.",
                "Issue creation blocked: unredacted secret.",
            )

        body = self._build_body(repository, commit_id, findings)
        return self._create_issue(repository, title, body)

    @staticmethod
    def _invalid(message: str) -> dict:
        return fail("INVALID_PAYLOAD", message, "Invalid issue payload.")

    @staticmethod
    def _clean_findings(findings: Any) -> Optional[list[dict]]:
        """Returns cleaned findings, or None if the list is missing or malformed."""
        if not isinstance(findings, list) or not 1 <= len(findings) <= MAX_FINDINGS:
            return None
        cleaned = []
        for finding in findings:
            if not isinstance(finding, dict):
                return None
            finding_type = finding.get("type")
            severity = finding.get("severity")
            line = finding.get("line")
            fields = {key: finding.get(key) for key in ("file", "evidence", "recommendation")}
            if not isinstance(finding_type, str) or not _TYPE_PATTERN.fullmatch(finding_type):
                return None
            if not isinstance(severity, str) or severity not in _SEVERITIES:
                return None
            if line is not None and (not isinstance(line, int) or isinstance(line, bool) or line < 1):
                return None
            if not all(isinstance(value, str) and value.strip() for value in fields.values()):
                return None
            cleaned.append(
                {
                    "type": finding_type,
                    "severity": severity,
                    "line": line,
                    **{key: _one_line(value) for key, value in fields.items()},
                }
            )
        return cleaned

    @staticmethod
    def _build_body(repository: str, commit_id: str, findings: list[dict]) -> str:
        counts = {sev: sum(f["severity"] == sev for f in findings) for sev in _SEVERITIES}
        breakdown = ", ".join(f"{n} {sev}" for sev, n in counts.items() if n)
        lines = [
            "## Security review findings",
            "",
            f"- **Repository:** {repository}",
            f"- **Commit:** `{commit_id}`",
            f"- **Findings:** {len(findings)} ({breakdown})",
            "",
            "Evidence is redacted: secret values are shown as `[REDACTED]`.",
        ]
        for number, finding in enumerate(findings, start=1):
            lines += [
                "",
                f"### {number}. {finding['type']} ({finding['severity']})",
                f"- **Severity:** {finding['severity']}",
                f"- **File:** `{finding['file']}`",
                f"- **Line:** {finding['line'] if finding['line'] else 'unknown'}",
                "- **Evidence:**",
                "```",
                finding["evidence"],
                "```",
                f"- **Recommendation:** {finding['recommendation']}",
            ]
        lines += ["", "---", "*Created after explicit human approval by the Security Commit Reviewer fallback.*"]
        return "\n".join(lines) + "\n"

    def _create_issue(self, repository: str, title: str, body: str) -> dict:
        # The body goes through stdin (`--body-file -`) to avoid command-line length limits.
        command = [
            self.gh_executable, "issue", "create",
            "--repo", repository,
            "--title", title,
            "--body-file", "-",
        ]
        env = {**os.environ, "GH_PROMPT_DISABLED": "1", "NO_COLOR": "1"}
        logger.info("Creating GitHub issue in %s (no automatic retry).", repository)
        try:
            completed = subprocess.run(
                command,
                input=body.encode("utf-8"),
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return fail(
                "TIMEOUT",
                f"gh did not finish within {self.timeout_seconds} seconds. The issue may or may "
                "not have been created: check the repository before trying again.",
                "GitHub CLI timed out.",
            )
        except FileNotFoundError:
            return fail("GH_NOT_FOUND", "The GitHub CLI (gh) was not found.", "GitHub CLI is not installed.")
        except OSError as exc:
            return fail("GH_FAILED", f"Could not start gh: {type(exc).__name__}.", "GitHub CLI failed to start.")

        stdout = completed.stdout.decode("utf-8", errors="replace")
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()

        if completed.returncode != 0:
            return self._failure_from_stderr(completed.returncode, stderr)

        match = None
        for line in reversed(stdout.strip().splitlines()):
            match = _ISSUE_URL_PATTERN.search(line)
            if match:
                break
        if not match:
            return fail(
                "UNVERIFIED_RESULT",
                "gh exited successfully but returned no issue URL. The issue may have been "
                "created: check the repository before trying again.",
                "Issue creation could not be verified.",
            )

        issue_url = match.group(0)
        issue_number = int(match.group(1))
        summary = f"Created GitHub issue #{issue_number} in {repository}."
        logger.info(summary)
        return ok(
            summary,
            {"issue_url": issue_url, "issue_number": issue_number, "repository": repository},
        )

    @staticmethod
    def _failure_from_stderr(returncode: int, stderr: str) -> dict:
        lowered = stderr.lower()
        if any(marker in lowered for marker in _AUTH_MARKERS):
            return fail(
                "GH_AUTH_FAILED",
                "GitHub CLI is not authenticated. Run `gh auth login`. No issue was created.",
                "GitHub authentication failed.",
            )
        if any(marker in lowered for marker in _NOT_FOUND_MARKERS):
            return fail(
                "REPOSITORY_NOT_FOUND",
                "Repository was not found, or you do not have access to it. No issue was created.",
                "Repository not found.",
            )
        return fail(
            "GH_FAILED",
            f"gh exited with code {returncode}: {stderr}",
            "GitHub issue creation failed.",
        )


def _one_line(text: str) -> str:
    """Keeps a value on one line and free of backticks so it cannot break the Markdown."""
    return " ".join(text.split()).replace("`", "'")[:MAX_FIELD_CHARS]
