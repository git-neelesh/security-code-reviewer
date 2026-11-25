"""GitTool: read-only retrieval of a commit's diff and changed files via `git show`."""

import logging
import os
import re
import subprocess
import time
from typing import Optional

from fallback.result import fail, ok

logger = logging.getLogger(__name__)

_COMMIT_ID_PATTERN = re.compile(r"^[0-9a-fA-F]{4,64}$")
_DIFF_START_PREFIXES = ("diff --git ", "diff --cc ", "diff --combined ")
_INVALID_COMMIT_MARKERS = (
    "bad object",
    "bad revision",
    "unknown revision",
    "ambiguous argument",
    "not a valid object",
    "invalid object name",
)
_INVALID_REPOSITORY_MARKERS = ("not a git repository",)
_RECOVERABLE_MARKERS = (".lock", "another git process")


class GitTool:
    """Fetches commit metadata, changed files and the diff using `git show` only.

    The tool never writes to the repository: it only runs `git show`, never uses a
    shell, and disables external diff drivers.
    """

    def __init__(
        self,
        timeout_seconds: float = 15.0,
        git_executable: str = "git",
        max_diff_chars: int = 1_000_000,
        retry_delay_seconds: float = 0.5,
    ) -> None:
        self.timeout_seconds = timeout_seconds
        self.git_executable = git_executable
        self.max_diff_chars = max_diff_chars
        self.retry_delay_seconds = retry_delay_seconds

    def run(self, repository: str, commit_id: str) -> dict:
        """Returns {"success", "summary", "data", "error"} for the given commit.

        On success `data` holds commit_id, author, date, message, changed_files,
        diff and truncated. The raw diff is intended only as input for ScannerTool
        and must not be logged or shown to users.
        """
        if not isinstance(commit_id, str) or not _COMMIT_ID_PATTERN.fullmatch(commit_id.strip()):
            return fail(
                "INVALID_COMMIT",
                "Commit ID must be a 4-64 character hexadecimal SHA.",
                "Invalid commit ID.",
            )
        commit_id = commit_id.strip()

        repo_path = self._validate_repository(repository)
        if repo_path is None:
            return fail(
                "INVALID_REPOSITORY",
                "Repository path is empty, missing or not a directory.",
                "Invalid repository path.",
            )

        command = [
            self.git_executable,
            "--no-pager",
            "-c",
            "core.quotepath=off",
            "-C",
            repo_path,
            "show",
            "--no-ext-diff",
            "--no-textconv",
            "--format=commit:%H%nauthor:%an%ndate:%aI%nmessage:%s",
            "--patch-with-raw",
            f"{commit_id}^{{commit}}",
        ]

        result = self._run_with_single_retry(command, commit_id)
        if isinstance(result, dict):
            return result
        return self._build_result(result, commit_id)

    @staticmethod
    def _validate_repository(repository: object) -> Optional[str]:
        if not isinstance(repository, (str, os.PathLike)):
            return None
        try:
            path = os.fspath(repository)
        except TypeError:
            return None
        if not isinstance(path, str) or not path.strip() or "\x00" in path:
            return None
        path = path.strip()
        return os.path.abspath(path) if os.path.isdir(path) else None

    def _run_with_single_retry(self, command: list[str], commit_id: str):
        """Runs git, retrying once for recoverable failures. Returns stdout text or an error dict."""
        last_error: Optional[dict] = None
        for attempt in (1, 2):
            outcome = self._run_once(command)
            if isinstance(outcome, str):
                return outcome
            error, recoverable = outcome
            last_error = error
            logger.warning(
                "GitTool attempt %d for commit %s failed: %s",
                attempt,
                commit_id[:12],
                error["error"]["code"],
            )
            if not recoverable or attempt == 2:
                break
            time.sleep(self.retry_delay_seconds)
        return last_error

    def _run_once(self, command: list[str]):
        """Returns stdout text on success, otherwise (error_result, recoverable)."""
        env = {**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                timeout=self.timeout_seconds,
                check=False,
                shell=False,
                env=env,
            )
        except subprocess.TimeoutExpired:
            return (
                fail(
                    "TIMEOUT",
                    f"git show did not finish within {self.timeout_seconds} seconds.",
                    "Git command timed out.",
                ),
                True,
            )
        except FileNotFoundError:
            return (
                fail("GIT_NOT_FOUND", "The git executable was not found.", "Git is not installed."),
                False,
            )
        except OSError as exc:
            return (
                fail("GIT_FAILED", f"Could not start git: {type(exc).__name__}.", "Git failed to start."),
                False,
            )

        if completed.returncode == 0:
            return completed.stdout.decode("utf-8", errors="replace")

        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        lowered = stderr.lower()
        if any(marker in lowered for marker in _INVALID_REPOSITORY_MARKERS):
            return (
                fail("INVALID_REPOSITORY", "The path is not a git repository.", "Invalid repository."),
                False,
            )
        if any(marker in lowered for marker in _INVALID_COMMIT_MARKERS):
            return (
                fail("INVALID_COMMIT", "The commit was not found in the repository.", "Commit not found."),
                False,
            )
        return (
            fail(
                "GIT_FAILED",
                f"git exited with code {completed.returncode}: {stderr}",
                "Git command failed.",
            ),
            any(marker in lowered for marker in _RECOVERABLE_MARKERS),
        )

    def _build_result(self, output: str, commit_id: str) -> dict:
        metadata = {"commit": "", "author": "", "date": "", "message": ""}
        changed_files: list[dict] = []
        diff_lines: list[str] = []
        in_diff = False

        for line in output.splitlines():
            if in_diff:
                diff_lines.append(line)
            elif line.startswith(_DIFF_START_PREFIXES):
                in_diff = True
                diff_lines.append(line)
            elif line.startswith(":"):
                entry = self._parse_raw_entry(line)
                if entry:
                    changed_files.append(entry)
            else:
                for key in metadata:
                    prefix = f"{key}:"
                    if line.startswith(prefix) and not metadata[key]:
                        metadata[key] = line[len(prefix):]
                        break

        diff = "\n".join(diff_lines)
        truncated = len(diff) > self.max_diff_chars
        if truncated:
            diff = diff[: self.max_diff_chars]

        full_sha = metadata["commit"] or commit_id
        data = {
            "commit_id": full_sha,
            "author": metadata["author"],
            "date": metadata["date"],
            "message": metadata["message"],
            "changed_files": changed_files,
            "diff": diff,
            "truncated": truncated,
        }
        summary = (
            f"Retrieved commit {full_sha[:12]} with {len(changed_files)} changed file(s)"
            f"{' (diff truncated)' if truncated else ''}."
        )
        logger.info(summary)
        return ok(summary, data)

    @staticmethod
    def _parse_raw_entry(line: str) -> Optional[dict]:
        """Parses `:<modes> <shas> <status>\\t<path>[\\t<new path>]` from `--raw` output."""
        fields = line.split("\t")
        if len(fields) < 2:
            return None
        status_tokens = fields[0].split()
        if not status_tokens:
            return None
        return {"path": fields[-1], "status": status_tokens[-1][0]}
