"""repoFetchAgent: Fetches commit metadata, diffs, and modified code files from GitHub via MCP."""

from google.adk.agents import LlmAgent
from google.adk.models.google_llm import Gemini
from google.genai import types

from fetch_status import record_commit_fetch_status
from tools import (
    create_github_readonly_mcp_toolset,
    get_commit_dummy_tool,
    get_diff_dummy_tool,
    get_file_contents_dummy_tool,
    github_mcp_methods_tool,
    list_commits_dummy_tool,
)

MODEL_NAME = "gemini-3.5-flash-lite"

retry_config = types.HttpRetryOptions(
    attempts=5,
    exp_base=7,
    initial_delay=1,
    http_status_codes=[429, 500, 503, 504],
)


def repo_fetch_agent() -> LlmAgent:
    """Creates the agent responsible for fetching commit and file details from GitHub MCP."""
    return LlmAgent(
        name="repoFetchAgent",
        model=Gemini(model=MODEL_NAME, retry_options=retry_config),
        description="Fetches commit metadata, diffs, and modified code files from GitHub via MCP.",
        instruction="""You are a GitHub Repository Fetch Specialist.
The user will provide a repository name (e.g., 'owner/repo') and a commit ID (SHA).

Your responsibilities:
1. Extract the exact repository owner, repository name, and commit ID from the user's request.
2. Call the GitHub MCP `get_commit` tool first using only `owner`, `repo`, and `sha`.
   Do not pass optional parameters such as `detail`, `page`, or any extras.
3. MCP failure fallback:
   - If MCP connection fails, MCP initialization fails, the server is unavailable, or authentication/authorization fails, immediately call `get_commit_dummy` with the exact owner, repo, and sha.
   - Do not call any dummy tool merely because earlier text mentions MCP fallback. Treat the actual MCP tool result as the source of truth.
4. MCP repository/commit-not-found behavior remains unchanged only when MCP itself successfully responds:
   - `FETCH_STATUS: FAILED` followed by `FETCH_FAILURE: REPOSITORY_NOT_FOUND`
   - `FETCH_STATUS: FAILED` followed by `FETCH_FAILURE: COMMIT_NOT_FOUND`
   - `FETCH_STATUS: FAILED` followed by `FETCH_FAILURE: ACCESS_DENIED`
   - `FETCH_STATUS: FAILED` followed by `FETCH_FAILURE: OTHER`
   However, for server connection, server authentication, or MCP tool execution failure, use the dummy fallback instead of inventing a GitHub failure.
5. For real MCP success or dummy fallback success, begin with `FETCH_STATUS: SUCCESS` and present:
   - Repository Name (`owner/repo`)
   - Commit ID (`sha`)
   - Commit Message & Author
   - Source (`mcp` or `dummy_fallback`)
   - Modified Files and complete code diffs/patches
   - State explicitly that dummy data is simulated when the source is `dummy_fallback`.
""",
        tools=[
            create_github_readonly_mcp_toolset(),
            github_mcp_methods_tool,
            get_commit_dummy_tool,
            get_diff_dummy_tool,
            get_file_contents_dummy_tool,
            list_commits_dummy_tool,
        ],
        output_key="commit_code_details",
        after_agent_callback=record_commit_fetch_status,
    )
