"""Shared result contract and secret redaction helpers for the fallback tools."""

import re
from typing import Any, Optional

REDACTED = "[REDACTED]"
MAX_ERROR_MESSAGE_CHARS = 300

# Safety net for free text (errors, summaries, logs). Scanning for findings is
# handled separately by ScannerTool.
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([\w.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)[\w.-]*)"
    r"(\s*[:=]\s*)([\"']?)([^\s\"',;]+)\3"
)
_KNOWN_TOKEN_PATTERNS = (
    re.compile(r"\b(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"),
)


def redact_text(text: Any) -> str:
    """Returns text with password/token/API-key style values replaced by [REDACTED]."""
    redacted = str(text)
    redacted = _ASSIGNMENT_PATTERN.sub(rf"\1\2\3{REDACTED}\3", redacted)
    for pattern in _KNOWN_TOKEN_PATTERNS:
        redacted = pattern.sub(REDACTED, redacted)
    return redacted


def ok(summary: str, data: Any) -> dict:
    """Builds a successful result in the common fallback-tool contract."""
    return {"success": True, "summary": redact_text(summary), "data": data, "error": None}


def fail(code: str, message: str, summary: Optional[str] = None) -> dict:
    """Builds a failed result. The message and summary are always redacted and bounded."""
    safe_message = redact_text(message)[:MAX_ERROR_MESSAGE_CHARS]
    safe_summary = redact_text(summary) if summary else f"Operation failed: {code}"
    return {
        "success": False,
        "summary": safe_summary,
        "data": None,
        "error": {"code": code, "message": safe_message},
    }
