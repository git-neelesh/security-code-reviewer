"""Step-by-step audit trail written as JSON Lines (one JSON object per line).

Every value is redacted and size-limited before it is written. Raw diffs, evidence,
issue bodies and credentials are never accepted: keys that could carry them are dropped.
Each event is also sent to the standard `logging` module, so it lands in
security_reviewer.log through the existing configure_logging() setup.
"""

import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fallback.result import redact_text

logger = logging.getLogger(__name__)

AUDIT_LOG_ENV = "SECURITY_REVIEW_AUDIT_LOG"
DEFAULT_AUDIT_LOG = "security_reviewer_audit.jsonl"
MAX_VALUE_CHARS = 300
MAX_LIST_ITEMS = 20
_FORBIDDEN_KEY_PARTS = (
    "diff", "evidence", "body", "raw", "token", "password", "passwd",
    "secret", "authorization", "api_key", "apikey", "credential",
)


class AuditLogger:
    """Appends one audit event per call to a JSONL file."""

    def __init__(self, path: Optional[str] = None, run_id: Optional[str] = None) -> None:
        self.path = path or os.environ.get(AUDIT_LOG_ENV) or DEFAULT_AUDIT_LOG
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self._step = 0

    def record(
        self,
        action: str,
        tool: str,
        reason: str,
        outcome: str,
        *,
        repository: Optional[str] = None,
        commit_id: Optional[str] = None,
        backend: Optional[str] = None,
        approval_decision: Optional[str] = None,
        issue_number: Optional[int] = None,
        issue_url: Optional[str] = None,
        error_code: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> dict:
        """Writes one event and returns it. Never raises: audit problems must not stop a review."""
        self._step += 1
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "run_id": self.run_id,
            "step": self._step,
            "action": action,
            "tool": tool,
            "reason": reason,
            "repository": repository,
            "commit_id": commit_id,
            "backend": backend,
            "outcome": outcome,
            "approval_decision": approval_decision,
            "issue_number": issue_number,
            "issue_url": issue_url,
            "error_code": error_code,
            "details": details or {},
        }
        event = _safe(event)
        line = json.dumps(event, sort_keys=True, ensure_ascii=True)
        try:
            with open(self.path, "a", encoding="utf-8") as audit_file:
                audit_file.write(line + "\n")
        except OSError as exc:
            logger.warning("Could not write audit event: %s", type(exc).__name__)
        logger.info("AUDIT %s", line)
        return event


def _safe(value: Any) -> Any:
    """Redacts strings, drops risky keys and limits sizes."""
    if isinstance(value, str):
        return redact_text(value)[:MAX_VALUE_CHARS]
    if isinstance(value, dict):
        return {
            str(key): _safe(item)
            for key, item in value.items()
            if not any(part in str(key).lower() for part in _FORBIDDEN_KEY_PARTS)
        }
    if isinstance(value, (list, tuple)):
        return [_safe(item) for item in list(value)[:MAX_LIST_ITEMS]]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return redact_text(str(value))[:MAX_VALUE_CHARS]
