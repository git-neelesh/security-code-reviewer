"""ScannerTool: deterministic regex scan of the added lines of a git diff (no LLM)."""

import logging
import os
import re
import time
from typing import NamedTuple, Optional

from fallback.result import REDACTED, fail, ok, redact_text

logger = logging.getLogger(__name__)

MAX_LINE_CHARS = 2000  # longer lines are skipped to keep regex work bounded
MAX_EVIDENCE_CHARS = 200

_HUNK_HEADER = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_LOOKS_LIKE_DIFF = re.compile(r"^(?:diff --git |@@ )", re.MULTILINE)

# `key = value`, `key: value` or `"key": value`, but not `==`.
_SEPARATOR = r"[\"']?\s*(?::=|=(?!=)|:)\s*"
_VALUE = r"""(?:"(?P<dq>[^"]*)"|'(?P<sq>[^']*)'|(?P<bare>[^\s"',;#]+))"""

_PASSWORD_WORDS = r"(?:password|passwd|pwd)"
_TOKEN_WORDS = (
    r"(?:api[_-]?key|api[_-]?token|access[_-]?token|auth[_-]?token"
    r"|secret[_-]?key|client[_-]?secret|github[_-]?token)"
)

# Values that are clearly not a real secret.
_PLACEHOLDERS = {
    "none", "null", "changeme", "change_me", "change-me", "example", "todo",
    "your_password", "your-password", "your_api_key", "your-api-key",
    "xxx", "xxxx", "********", REDACTED.lower(),
}
_ENV_LOOKUP_PREFIXES = ("os.", "process.env", "env.", "system.getenv")
_CONFIG_EXTENSIONS = {".ini", ".cfg", ".conf", ".properties", ".yml", ".yaml", ".toml", ".env"}


class Rule(NamedTuple):
    rule_id: str
    finding_type: str
    severity: str
    pattern: re.Pattern
    recommendation: str
    is_secret: bool  # True: the matched value must be redacted and checked as a literal


RULES = (
    Rule(
        "hardcoded-password",
        "HARDCODED_PASSWORD",
        "HIGH",
        re.compile(rf"{_PASSWORD_WORDS}[\w-]*{_SEPARATOR}{_VALUE}", re.IGNORECASE),
        "Remove the hard-coded password. Load it from an environment variable or a "
        "secrets manager, and rotate it if it was ever real.",
        True,
    ),
    Rule(
        "hardcoded-api-key-or-token",
        "API_KEY_OR_TOKEN",
        "HIGH",
        re.compile(rf"{_TOKEN_WORDS}[\w-]*{_SEPARATOR}{_VALUE}", re.IGNORECASE),
        "Remove the hard-coded API key/token. Load it from an environment variable or a "
        "secrets manager, and revoke it if it was ever real.",
        True,
    ),
    Rule(
        "tls-verification-disabled",
        "UNSAFE_CONFIGURATION",
        "HIGH",
        re.compile(
            r"(?<![A-Za-z0-9])(?:verify[_-]?(?:ssl|tls|certs?|certificates?)"
            r"|(?:ssl|tls)[_-]?verify|verify|rejectUnauthorized)"
            rf"{_SEPARATOR}[\"']?(?:false|0|no|off)(?![A-Za-z0-9.])",
            re.IGNORECASE,
        ),
        "Keep TLS certificate verification enabled. Fix the certificate or trust store "
        "instead of turning verification off.",
        False,
    ),
    Rule(
        "debug-enabled",
        "UNSAFE_CONFIGURATION",
        "MEDIUM",
        re.compile(
            rf"(?<![A-Za-z0-9])debug(?![A-Za-z0-9]){_SEPARATOR}[\"']?(?:true|1|yes|on)(?![A-Za-z0-9])",
            re.IGNORECASE,
        ),
        "Disable debug mode in production. Read it from an environment variable that "
        "defaults to off.",
        False,
    ),
)


class _ScanTimeout(Exception):
    pass


class ScannerTool:
    """Scans only the added (+) lines of a unified git diff for security problems."""

    def __init__(self, timeout_seconds: float = 10.0) -> None:
        self.timeout_seconds = timeout_seconds

    def run(self, diff: str) -> dict:
        """Returns {"success", "summary", "data", "error"}.

        `diff` is the text from GitTool's result["data"]["diff"]. On success `data` is
        {"findings": [...], "count", "lines_scanned", "skipped_long_lines"}. Each finding
        has type, rule, severity, file, line, evidence (secret replaced by [REDACTED])
        and recommendation. A clean diff is a success with zero findings.
        """
        if not isinstance(diff, str):
            return fail("INVALID_INPUT", "Diff must be a string.", "Invalid scanner input.")
        if not diff.strip():
            return ok("Empty diff: nothing to scan.", self._data([], 0, 0))
        if not _LOOKS_LIKE_DIFF.search(diff):
            return fail(
                "INVALID_INPUT",
                "Input does not look like a unified git diff.",
                "Invalid scanner input.",
            )

        try:
            findings, lines_scanned, skipped = self._scan(diff)
        except _ScanTimeout:
            return fail(
                "TIMEOUT",
                f"Scan did not finish within {self.timeout_seconds} seconds.",
                "Scanner timed out.",
            )
        except Exception as exc:  # never include exc text: it could contain diff content
            return fail(
                "SCAN_FAILED",
                f"Scanner failed unexpectedly: {type(exc).__name__}.",
                "Scanner failed.",
            )

        summary = self._summary(findings, lines_scanned)
        logger.info(summary)
        return ok(summary, self._data(findings, lines_scanned, skipped))

    def _scan(self, diff: str):
        deadline = time.monotonic() + self.timeout_seconds
        findings: list[dict] = []
        current_file: Optional[str] = None
        new_line = 0
        in_hunk = False
        lines_scanned = 0
        skipped = 0

        for raw_line in diff.split("\n"):
            if time.monotonic() > deadline:
                raise _ScanTimeout()
            line = raw_line.rstrip("\r")

            if line.startswith("diff --git "):
                in_hunk = False
                current_file = None
                continue

            if not in_hunk:
                # Header area: only `+++ b/<path>` and the first `@@` matter.
                if line.startswith("+++ "):
                    current_file = self._parse_path(line[4:])
                    continue
                hunk = _HUNK_HEADER.match(line)
                if hunk:
                    in_hunk = True
                    new_line = int(hunk.group(1))
                continue

            hunk = _HUNK_HEADER.match(line)
            if hunk:
                new_line = int(hunk.group(1))
            elif line.startswith("+"):
                lines_scanned += 1
                if len(line) > MAX_LINE_CHARS:
                    skipped += 1
                else:
                    findings.extend(self._scan_added_line(line[1:], current_file, new_line))
                new_line += 1
            elif line.startswith("-") or line.startswith("\\"):
                continue  # removed lines and "\ No newline at end of file" are ignored
            else:
                new_line += 1  # context line

        return findings, lines_scanned, skipped

    @staticmethod
    def _parse_path(header_value: str) -> Optional[str]:
        path = header_value.split("\t")[0].strip().strip('"')
        if path == "/dev/null":
            return None
        return path[2:] if path.startswith("b/") else path

    def _scan_added_line(self, content: str, file_name: Optional[str], line_number: int) -> list[dict]:
        matched_rules: list[Rule] = []
        secret_spans: list[tuple[int, int]] = []
        is_config = self._is_config_file(file_name)

        for rule in RULES:
            found = False
            for match in rule.pattern.finditer(content):
                if rule.is_secret:
                    if not self._is_hardcoded(match, is_config):
                        continue
                    secret_spans.append(self._value_span(match))
                found = True
            if found:
                matched_rules.append(rule)

        if not matched_rules:
            return []

        evidence = self._build_evidence(content, secret_spans)
        return [
            {
                "type": rule.finding_type,
                "rule": rule.rule_id,
                "severity": rule.severity,
                "file": file_name,
                "line": line_number,
                "evidence": evidence,
                "recommendation": rule.recommendation,
            }
            for rule in matched_rules
        ]

    @staticmethod
    def _is_config_file(file_name: Optional[str]) -> bool:
        if not file_name:
            return False
        name = os.path.basename(file_name).lower()
        return name.startswith(".env") or os.path.splitext(name)[1] in _CONFIG_EXTENSIONS

    @staticmethod
    def _value_span(match: re.Match) -> tuple[int, int]:
        for group in ("dq", "sq", "bare"):
            if match.group(group) is not None:
                return match.span(group)
        return match.span()

    @staticmethod
    def _is_hardcoded(match: re.Match, is_config_file: bool) -> bool:
        """True when the matched value is a literal, not an env-var lookup or placeholder."""
        bare = match.group("bare")
        if bare is not None:
            # Unquoted values are only literals in config files (.env, .yml, ...). In code
            # they are expressions such as os.getenv(...) or other variables.
            if not is_config_file or any(char in bare for char in "()[]"):
                return False
            if bare.lower().startswith(_ENV_LOOKUP_PREFIXES):
                return False
            value = bare
        else:
            value = match.group("dq") if match.group("dq") is not None else match.group("sq")
        value = value.strip()
        if not value:
            return False
        if value.startswith(("$", "{", "<", "%")) or "${" in value or "{{" in value:
            return False
        return value.lower() not in _PLACEHOLDERS

    @staticmethod
    def _build_evidence(content: str, spans: list[tuple[int, int]]) -> str:
        for start, end in sorted(set(spans), reverse=True):
            content = content[:start] + REDACTED + content[end:]
        evidence = redact_text(content.strip())  # safety net for other secrets on the line
        return evidence[:MAX_EVIDENCE_CHARS]

    @staticmethod
    def _data(findings: list[dict], lines_scanned: int, skipped: int) -> dict:
        return {
            "findings": findings,
            "count": len(findings),
            "lines_scanned": lines_scanned,
            "skipped_long_lines": skipped,
        }

    @staticmethod
    def _summary(findings: list[dict], lines_scanned: int) -> str:
        if not findings:
            return f"Scanned {lines_scanned} added line(s): no security findings."
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        breakdown = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items()))
        return f"Scanned {lines_scanned} added line(s): {len(findings)} finding(s) ({breakdown})."
