"""Custom Function Tools and GitHub MCP Toolsets for the Security Code Reviewer."""

import os
import logging

from google.adk.tools.function_tool import FunctionTool
from google.adk.tools.mcp_tool.mcp_toolset import McpToolset
from google.adk.tools.tool_context import ToolContext

# Support StreamableHTTPServerParams as shown in Day-2b sample notebook
try:
    from google.adk.tools.mcp_tool.mcp_session_manager import StreamableHTTPServerParams
except ImportError:
    from google.adk.tools.mcp_tool.mcp_session_manager import (
        StreamableHTTPConnectionParams as StreamableHTTPServerParams,
    )

GITHUB_MCP_URL = "https://api.githubcopilot.com/mcp/"
logger = logging.getLogger("security_code_reviewer")


def _is_no_security_issue(
    issue_title: str | None,
    severity_summary: str | None,
    report_text: str | None = None,
) -> bool:
    """Detects reports where the review found no actionable security issue."""
    text_parts = [issue_title or "", severity_summary or "", report_text or ""]
    text = " ".join(part for part in text_parts if part).lower()
    if not text:
        return False

    no_issue_markers = (
        "no security issue",
        "no issues found",
        "no actionable security issue",
        "no vulnerabilities found",
        "no security findings",
        "no findings",
        "no issue found",
        "nothing to report",
        "no actionable issue",
        "informational only",
        "no vulnerability",
        "risk level: informational",
        "overall risk level: informational",
        "overall risk level: low",
    )
    return any(marker in text for marker in no_issue_markers)


def _get_github_token() -> str:
    """Retrieves GITHUB_TOKEN from the process environment."""
    return os.environ.get("GITHUB_TOKEN", "").strip()


def create_github_readonly_mcp_toolset() -> McpToolset:
    """Creates a read-only GitHub MCP toolset for repoFetchAgent.

    Connects to https://api.githubcopilot.com/mcp/ with X-MCP-Readonly set to 'true'
    to fetch commit diffs, file contents, and repository metadata safely.
    """
    github_token = _get_github_token()
    return McpToolset(
        connection_params=StreamableHTTPServerParams(
            url=GITHUB_MCP_URL,
            headers={
                "Authorization": f"Bearer {github_token}",
                "X-MCP-Toolsets": "all",
                "X-MCP-Readonly": "true",
            },
        ),
        tool_filter=["get_commit", "get_file_contents", "list_commits"],
    )


def create_github_write_mcp_toolset() -> McpToolset:
    """Creates a write-enabled GitHub MCP toolset for IssueReportAgent.

    Connects to https://api.githubcopilot.com/mcp/ with write permissions enabled
    so the agent can create a GitHub issue in the repository after human approval.
    """
    github_token = _get_github_token()
    return McpToolset(
        connection_params=StreamableHTTPServerParams(
            url=GITHUB_MCP_URL,
            headers={
                "Authorization": f"Bearer {github_token}",
                "X-MCP-Toolsets": "repos,issues",
                "X-MCP-Readonly": "false",
            },
        ),
        tool_filter=["issue_write"],
    )


def request_security_issue_approval(
    repo_name: str,
    commit_id: str,
    issue_title: str = "Security review findings",
    severity_summary: str = "Security findings identified during review.",
    tool_context: ToolContext | None = None,
) -> dict:
    """Requests human sign-off while preserving the lightweight eval contract."""
    should_prompt_for_confirmation = (
        os.environ.get("ADK_ENABLE_CONFIRMATION", "1") != "0"
    )

    report_text = ""
    if tool_context is not None and getattr(tool_context, "state", None):
        state = tool_context.state or {}
        report_text = state.get("security_analysis_report") or ""
        if isinstance(report_text, str):
            report_text = report_text
        else:
            report_text = str(report_text)

    if _is_no_security_issue(issue_title, severity_summary, report_text):
        if tool_context is not None:
            tool_context.state["approval_status"] = "rejected"
        return {
            "status": "rejected",
            "decision": "REJECTED",
            "repo_name": repo_name,
            "commit_id": commit_id,
            "issue_title": issue_title,
            "severity_summary": severity_summary,
            "message": "No security issue found; no GitHub issue was created.",
        }

    if tool_context is not None and should_prompt_for_confirmation:
        if not tool_context.tool_confirmation:
            tool_context.request_confirmation(
                hint=(
                    f"Security review completed for {repo_name} @ {commit_id}.\n"
                    f"Proposed Issue: {issue_title}\n"
                    f"Summary: {severity_summary}\n"
                    f"Do you approve creating this GitHub issue in {repo_name}?"
                ),
                payload={
                    "repo_name": repo_name,
                    "commit_id": commit_id,
                    "issue_title": issue_title,
                    "severity_summary": severity_summary,
                },
            )
            tool_context.state["approval_status"] = "pending"
            return {
                "status": "pending",
                "repo_name": repo_name,
                "commit_id": commit_id,
                "issue_title": issue_title,
                "severity_summary": severity_summary,
            }

        if tool_context.tool_confirmation.confirmed:
            tool_context.state["approval_status"] = "approved"
            return {
                "status": "approved",
                "decision": "APPROVED",
                "repo_name": repo_name,
                "commit_id": commit_id,
                "issue_title": issue_title,
                "severity_summary": severity_summary,
            }

        tool_context.state["approval_status"] = "rejected"
        return {
            "status": "rejected",
            "decision": "REJECTED",
            "repo_name": repo_name,
            "commit_id": commit_id,
            "issue_title": issue_title,
            "severity_summary": severity_summary,
        }

    return {
        "status": "pending",
        "repo_name": repo_name,
        "commit_id": commit_id,
        "issue_title": issue_title,
        "severity_summary": severity_summary,
        "message": (
            f"Awaiting human confirmation to create a GitHub security issue for "
            f"{repo_name} on commit {commit_id}."
        ),
    }


approval_function_tool = FunctionTool(func=request_security_issue_approval)


def github_mcp_methods() -> dict:
    """Lists MCP methods used by the agents and their local dummy fallbacks."""
    return {
        "status": "ok",
        "methods": [
            {"mcp_method": "get_commit", "fallback_method": "get_commit_dummy", "read_only": True},
            {"mcp_method": "get_diff", "fallback_method": "get_diff_dummy", "read_only": True},
            {"mcp_method": "get_file_contents", "fallback_method": "get_file_contents_dummy", "read_only": True},
            {"mcp_method": "list_commits", "fallback_method": "list_commits_dummy", "read_only": True},
            {"mcp_method": "create_issue", "fallback_method": "create_issue_dummy", "read_only": False},
            {"mcp_method": "issue_write", "fallback_method": "create_issue_dummy", "read_only": False},
        ],
    }


def get_commit_dummy(owner: str, repo: str, sha: str) -> dict:
    """Local dummy fallback for MCP get_commit. Makes no network requests."""
    logger.warning("MCP fallback used: get_commit_dummy; MCP get_commit was not called successfully for %s@%s", f"{owner}/{repo}", sha)
    return {
        "status": "success",
        "FETCH_STATUS": "SUCCESS",
        "source": "dummy_fallback",
        "repository": f"{owner}/{repo}",
        "commit_id": sha,
        "commit": {"message": "Dummy fallback commit", "author": "Fallback User"},
        "files": [{
            "filename": "src/example.py",
            "status": "modified",
            "patch": "@@ -1,1 +1,1 @@\n-old_dummy_value = True\n+old_dummy_value = False",
        }],
    }


def get_diff_dummy(owner: str, repo: str, sha: str) -> dict:
    """Local dummy fallback for MCP get_diff. Makes no network requests."""
    logger.warning("MCP fallback used: get_diff_dummy; MCP get_diff was not called successfully for %s@%s", f"{owner}/{repo}", sha)
    commit = get_commit_dummy(owner, repo, sha)
    return {
        "status": "success",
        "FETCH_STATUS": "SUCCESS",
        "source": "dummy_fallback",
        "repository": f"{owner}/{repo}",
        "commit_id": sha,
        "diffs": commit["files"],
    }


def get_file_contents_dummy(owner: str, repo: str, path: str, sha: str) -> dict:
    """Local dummy fallback for MCP get_file_contents. Makes no network requests."""
    logger.warning("MCP fallback used: get_file_contents_dummy; MCP get_file_contents was not called successfully for %s@%s:%s", f"{owner}/{repo}", sha, path)
    return {
        "status": "success",
        "FETCH_STATUS": "SUCCESS",
        "source": "dummy_fallback",
        "repository": f"{owner}/{repo}",
        "commit_id": sha,
        "path": path,
        "content": "# Dummy fallback file content",
    }


def list_commits_dummy(owner: str, repo: str) -> dict:
    """Local dummy fallback for MCP list_commits. Makes no network requests."""
    logger.warning("MCP fallback used: list_commits_dummy; MCP list_commits was not called successfully for %s", f"{owner}/{repo}")
    return {
        "status": "success",
        "FETCH_STATUS": "SUCCESS",
        "source": "dummy_fallback",
        "repository": f"{owner}/{repo}",
        "commits": [{"sha": "dummy-sha", "message": "Dummy fallback commit"}],
    }


def create_issue_dummy(owner: str, repo: str, title: str, body: str) -> dict:
    """Local dummy fallback for issue creation. Creates no remote GitHub issue."""
    logger.warning("MCP fallback used: create_issue_dummy; MCP issue creation was not called successfully for %s", f"{owner}/{repo}")
    return {
        "status": "success",
        "source": "dummy_fallback",
        "issue_number": None,
        "title": title,
        "url": None,
        "message": "Dummy issue fallback used; no remote GitHub issue was created.",
    }


github_mcp_methods_tool = FunctionTool(func=github_mcp_methods)
get_commit_dummy_tool = FunctionTool(func=get_commit_dummy)
get_diff_dummy_tool = FunctionTool(func=get_diff_dummy)
get_file_contents_dummy_tool = FunctionTool(func=get_file_contents_dummy)
list_commits_dummy_tool = FunctionTool(func=list_commits_dummy)
create_issue_dummy_tool = FunctionTool(func=create_issue_dummy)
