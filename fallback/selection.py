"""Chooses between the GitHub MCP tools and the local fallback tools.

Rules, in order:
1. SECURITY_REVIEW_FORCE_FALLBACK=1 (or true/yes/on) -> fallback, MCP is not contacted.
2. The MCP URL (GITHUB_MCP_URL, or the default) does not answer a quick probe -> fallback.
3. Otherwise -> MCP.
"""

import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Mapping, Optional

DEFAULT_GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"
MCP_URL_ENV = "GITHUB_MCP_URL"
FORCE_FALLBACK_ENV = "SECURITY_REVIEW_FORCE_FALLBACK"
_TRUE_VALUES = {"1", "true", "yes", "on"}


def get_github_mcp_url(env: Optional[Mapping[str, str]] = None) -> str:
    """Returns the MCP URL: GITHUB_MCP_URL if set, otherwise the GitHub default."""
    env = os.environ if env is None else env
    return (env.get(MCP_URL_ENV) or "").strip() or DEFAULT_GITHUB_MCP_URL


def force_fallback_enabled(env: Optional[Mapping[str, str]] = None) -> bool:
    env = os.environ if env is None else env
    return (env.get(FORCE_FALLBACK_ENV) or "").strip().lower() in _TRUE_VALUES


def is_mcp_reachable(url: str, timeout_seconds: float = 3.0) -> bool:
    """True if the server answers at all, even with 401/405. No credentials are sent."""
    if urllib.parse.urlparse(url).scheme not in ("http", "https"):
        return False  # also stops file:// and other schemes from being opened
    try:
        with urllib.request.urlopen(url, timeout=timeout_seconds):
            return True
    except urllib.error.HTTPError:
        return True  # the server replied, so it is up
    except (urllib.error.URLError, OSError, ValueError):
        return False


def select_backend(
    env: Optional[Mapping[str, str]] = None,
    probe: Callable[[str], bool] = is_mcp_reachable,
) -> dict:
    """Returns {"path": "mcp" | "fallback", "reason": str}."""
    if force_fallback_enabled(env):
        return {"path": "fallback", "reason": f"{FORCE_FALLBACK_ENV} is set"}
    if not probe(get_github_mcp_url(env)):
        return {"path": "fallback", "reason": "GitHub MCP server is unreachable"}
    return {"path": "mcp", "reason": "GitHub MCP server is reachable"}
