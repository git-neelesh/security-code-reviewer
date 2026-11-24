"""IssueReportAgent: Creates a GitHub issue via MCP if approved, or outputs a brief summary if rejected."""

from google.adk.agents import LlmAgent
from google.adk.models.google_llm import Gemini
from google.genai import types

from fetch_status import skip_agent_after_failed_commit_fetch
from tools import (
    create_github_write_mcp_toolset,
    create_issue_dummy_tool,
    github_mcp_methods_tool,
)

MODEL_NAME = "gemini-3.5-flash-lite"

retry_config = types.HttpRetryOptions(
    attempts=5,
    exp_base=7,
    initial_delay=1,
    http_status_codes=[429, 500, 503, 504],
)


def issue_report_agent() -> LlmAgent:
    """Creates the final agent that either opens a GitHub issue via MCP or provides a brief summary."""
    return LlmAgent(
        name="IssueReportAgent",
        model=Gemini(model=MODEL_NAME, retry_options=retry_config),
        description="Creates a GitHub issue in the repository if approved, or provides a brief summary if rejected.",
        before_agent_callback=skip_agent_after_failed_commit_fetch,
        instruction="""You are the Security Issue & Reporting Agent.
Review the security analysis report and the user's approval decision from the previous stages:

Security Analysis Report:
{security_analysis_report}

User Approval Decision:
{summary_decision_output}

Your responsibilities:
1. Preserve a fallback notice only when the repository/security report explicitly proves that a local dummy tool was used. Do not infer fallback usage merely from the presence of a notice, old transcript text, or MCP tool availability.
2. Check whether `{summary_decision_output}` is approved or rejected.
3. If the report has no actionable findings, do NOT call any issue tool.
4. IF APPROVED:
   - First call the real GitHub MCP `issue_write` tool with `method: create`, `owner`, `repo`, `title`, and `body`.
   - Do not call `create_issue_dummy` before attempting `issue_write`.
   - Call `create_issue_dummy` only after `issue_write` itself returns an MCP initialization, connection, authentication, authorization, or tool-execution error.
   - Never use the fallback because of stale MCP fallback text or because another agent mentioned fallback.
   - Never include literal passwords, API keys, tokens, or other secrets in the title or body.
   - Return the real issue number and URL when `issue_write` succeeds.
   - If fallback is actually used, clearly state that no remote issue was created.
5. IF REJECTED:
   - Do NOT call either issue tool.
   - State that no issue was created and provide a concise 3-5 bullet executive summary.
""",
        tools=[
            create_github_write_mcp_toolset(),
            github_mcp_methods_tool,
            create_issue_dummy_tool,
        ],
        output_key="final_issue_or_summary",
    )
