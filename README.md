# Autonomous Security Commit Reviewer (`google-adk`)

An AI-assisted security review for Git commits. Given a repository and a commit, it looks for security problems in the lines that commit **added**, asks a human whether a GitHub issue should be opened, and creates the issue only after an explicit YES. Every step is written to an audit trail.

The MCP path is a 4-stage multi-agent security code review pipeline built with the [Google Agent Development Kit (ADK)](https://google.github.io/adk-docs/), modeled directly after your Day 1–4 Kaggle course notebooks.

The project supports two paths that produce equivalent results:

| Path | What it uses | When it is used |
|---|---|---|
| **MCP path** | A 4-agent ADK pipeline (Gemini) that talks to the GitHub MCP server | MCP is reachable and the fallback is not forced |
| **Local functional-tool fallback** | Plain Python tools (`git`, a regex scanner, the `gh` CLI), no LLM and no MCP | MCP is unreachable, or you force the fallback |

The fallback is **additive**: the MCP implementation is unchanged.

## Contents

1. [Architecture](#architecture)
2. [Functional fallback](#functional-fallback)
3. [Security detection](#security-detection)
4. [Human approval and safety](#human-approval-and-safety)
5. [Prerequisites and setup](#prerequisites-and-setup)
6. [How to run](#how-to-run)
7. [Testing](#testing)
8. [Audit logging](#audit-logging)
9. [Demo scenario](#demo-scenario)
10. [Known limitations](#known-limitations)
11. [Project structure](#project-structure)

## Architecture

`python -m workflow` first chooses a path (`select_backend()` in `fallback/selection.py`), then runs it:

```text
python -m workflow --repo owner/repo --commit <sha> [--repo-path <local clone>]
        │
        ▼
 select_backend()
   ├─ SECURITY_REVIEW_FORCE_FALLBACK=1 ........ -> fallback (MCP is not contacted)
   ├─ MCP URL does not answer a quick probe ... -> fallback
   └─ otherwise ............................... -> MCP path
```

### MCP path (4-agent ADK pipeline)

```text
User Input (repo_name, commit_id)
       │
       ▼
┌────────────────────────────────────────────────────────────────────────────┐
│ SequentialAgent: SecurityCodeReviewPipeline                                │
│ (Wrapped in App with ResumabilityConfig(is_resumable=True))                │
├────────────────────────────────────────────────────────────────────────────┤
│ 1. repoFetchAgent()  (repo_fetch_agent.py)                                 │
│    • Connects to https://api.githubcopilot.com/mcp/ (Read-Only)            │
│    • Fetches commit metadata, diffs, and modified files                    │
│    • Writes -> session.state["commit_code_details"]                        │
│    • Stops with a clear error if the repository/commit cannot be fetched   │
│                                                                            │
│ 2. securityReviewAgent()  (security_review_agent.py)                       │
│    • Reads {commit_code_details}                                           │
│    • Analyzes diff for OWASP Top 10, secrets, auth, and injection flaws    │
│    • Writes -> session.state["security_analysis_report"]                   │
│                                                                            │
│ 3. SummaryDecisionAgent()  (summary_decision_agent.py)                     │
│    • Reads {security_analysis_report}                                      │ 
│    • Calls `request_security_issue_approval` (ToolContext LRO)             │
│    • PAUSES execution (`adk_request_confirmation`) for Human Approval      │
│    • Writes -> session.state["summary_decision_output"]                    │
│                                                                            │
│ 4. IssueReportAgent()  (issue_report_agent.py)                             │
│    • Reads {security_analysis_report} & {summary_decision_output}          │
│    • IF APPROVED -> Calls GitHub MCP (`create_issue`) in same repo         │
│    • IF REJECTED -> Skips issue creation & outputs brief summary           │
│    • Writes -> session.state["final_issue_or_summary"]                     │
└────────────────────────────────────────────────────────────────────────────┘
```

### Local functional-tool fallback

Implemented in the `fallback/` package and run by `run_fallback_review()` (`fallback/pipeline.py`):

```text
 GitTool ──► ScannerTool ──► diagnosis ──► human approval ──► GitHubIssueTool
 git show    regex rules     risk level    y/N prompt          gh issue create
    │            │              │               │                    │
 failure      failure       no findings        NO / error           failure
    ▼            ▼              ▼               ▼                    ▼
 FETCH_FAILED SCAN_FAILED     CLEAN          REJECTED            ISSUE_FAILED
 (stop)       (stop)    (stop: no approval, (stop: no issue)   (no retry)
                         no issue)                                   │ success
                                                                     ▼
                                                              ISSUE_CREATED
```

| Component | Responsibility |
|---|---|
| `GitTool` | Runs a read-only `git show` on a local clone and returns the commit metadata, changed files and diff. |
| `ScannerTool` | Applies deterministic regex rules to the **added** lines of the diff and returns redacted findings. |
| Diagnosis (in `fallback/pipeline.py`) | Picks the highest severity as the risk level and builds the issue title. No findings means the run ends as `CLEAN`. |
| Human approval | Shows the redacted findings and asks y/N. Only an explicit YES continues. |
| `GitHubIssueTool` | Creates one issue with `gh issue create`, only for an approved, redacted payload. |
| `AuditLogger` | Writes the step-by-step JSONL audit trail. |

The raw diff only travels from `GitTool` to `ScannerTool` inside the pipeline. The returned result, the approval prompt, the issue and the audit log contain redacted findings only.

## Functional fallback

All three tools return the same dictionary, so the rest of the workflow does not need to know which tool produced it:

```python
{"success": bool, "summary": str, "data": ..., "error": ...}
```

- On success: `success=True`, `data` holds the payload, `error=None`.
- On failure: `success=False`, `data=None`, `error={"code": "...", "message": "..."}`.
- `summary` and `error` are always passed through redaction, and `error.message` is capped at 300 characters. Tools return errors instead of raising.

| Tool | Call | `data` on success | Error codes |
|---|---|---|---|
| `GitTool` | `GitTool().run(repository, commit_id)` | `commit_id`, `author`, `date`, `message`, `changed_files` (`path` + `status`), `diff`, `truncated` | `INVALID_COMMIT`, `INVALID_REPOSITORY`, `TIMEOUT`, `GIT_NOT_FOUND`, `GIT_FAILED` |
| `ScannerTool` | `ScannerTool().run(diff)` | `findings`, `count`, `lines_scanned`, `skipped_long_lines` | `INVALID_INPUT`, `TIMEOUT`, `SCAN_FAILED` |
| `GitHubIssueTool` | `GitHubIssueTool().run(approved_payload)` | `issue_url`, `issue_number`, `repository` | `NOT_APPROVED`, `INVALID_APPROVAL_TOKEN`, `INVALID_PAYLOAD`, `UNREDACTED_SECRET`, `GH_NOT_FOUND`, `GH_AUTH_FAILED`, `REPOSITORY_NOT_FOUND`, `TIMEOUT`, `GH_FAILED`, `UNVERIFIED_RESULT`, `ISSUE_TOOL_FAILED` |

Reliability: `GitTool` has a 15 s timeout and retries at most once, only for a timeout or a git lock error. `ScannerTool` has a 10 s timeout. `GitHubIssueTool` has a 30 s timeout and **never retries**.

`run_fallback_review()` returns the same structure, with `data["status"]` set to one of `FETCH_FAILED`, `SCAN_FAILED`, `CLEAN`, `REJECTED`, `ISSUE_CREATED` or `ISSUE_FAILED`. Only `ISSUE_CREATED` means an issue exists.

### How MCP or fallback is selected

| Setting | Effect |
|---|---|
| `SECURITY_REVIEW_FORCE_FALLBACK=1` (`true`, `yes` or `on` also work) | Always use the fallback; MCP is not contacted. |
| `GITHUB_MCP_URL=<url>` | Overrides the MCP server URL (default `https://api.githubcopilot.com/mcp/`). Both the probe and the MCP toolsets use it. Pointing it at a dead address (for example `http://127.0.0.1:9/`) simulates an MCP outage. |
| *(neither set)* | A single probe (3 s timeout, no credentials) is sent to the MCP URL. Any HTTP answer counts as reachable. No answer selects the fallback. |

The chosen path and the reason are printed and recorded in the audit log.

## Security detection

`ScannerTool` is deterministic: plain Python regular expressions, no LLM. It scans only lines **added** by the commit (`+` lines). Removed lines and diff headers (such as `+++ b/file.py`) are ignored. The file and new-file line number come from the diff headers and hunks.

| Rule | Finding type | Severity | Detects |
|---|---|---|---|
| `hardcoded-password` | `HARDCODED_PASSWORD` | HIGH | `password`, `passwd`, `pwd` (including `db_password` and similar) assigned a literal value |
| `hardcoded-api-key-or-token` | `API_KEY_OR_TOKEN` | HIGH | `api_key`, `api_token`, `access_token`, `auth_token`, `secret_key`, `client_secret`, `github_token` assigned a literal value |
| `tls-verification-disabled` | `UNSAFE_CONFIGURATION` | HIGH | `verify_ssl`, `ssl_verify`, `verify_tls`, `verify`, `rejectUnauthorized` and similar set to `false`, `0`, `no` or `off` |
| `debug-enabled` | `UNSAFE_CONFIGURATION` | MEDIUM | `DEBUG` set to `true`, `1`, `yes` or `on` |

Severity is fixed per rule (it is not scored). Each finding contains `type`, `rule`, `severity`, `file`, `line`, `evidence` and a `recommendation`. For example: load the secret from an environment variable or secrets manager and rotate it, keep TLS verification enabled, or disable debug mode in production.

**Evidence is always redacted.** The secret value is replaced with `[REDACTED]`, for example `API_KEY = "[REDACTED]"`, and a second redaction pass masks other well-known secret formats on the same line. A complete secret is never returned.

Not flagged as secrets: environment-variable lookups (`os.environ[...]`, `os.getenv(...)`, `process.env.X`), template values (`${VAR}`, `{{ x }}`), `<placeholders>`, empty values, `None`, `changeme`-style placeholders, `==` comparisons, `DEBUG = False` and `verify_ssl = True`.

## Human approval and safety

- A GitHub issue is created **only after an explicit human YES**. In the fallback, anything other than an explicit YES (NO, an empty answer, an error) counts as NO.
- **Rejection creates no issue**, and the issue tool is not called.
- **A clean commit creates no issue** and does not ask for approval.
- Git or scanner failures stop the workflow before any approval or issue.
- Issue creation is **never retried automatically**, because a retry could create a duplicate. After a timeout the issue may still exist, so check the repository before trying again.
- **Secrets are never exposed.** Findings, approval prompts, issue titles and bodies, results, errors, logs and the audit log use `[REDACTED]`. `GitHubIssueTool` also refuses a payload that still looks like it contains a secret (`UNREDACTED_SECRET`).
- `GitHubIssueTool` requires an approval token tied to the exact repository, commit, title and findings that were approved. If any of them change after approval, the issue is blocked (`INVALID_APPROVAL_TOKEN`). This is an integrity check, not a cryptographic signature.
- The fallback never modifies source code: `GitTool` only runs `git show`, and nothing rotates credentials.
- MCP path: the approval is the ADK `adk_request_confirmation` pause raised by `request_security_issue_approval`. Fallback path: the same y/N prompt and `--decision` options in the terminal.

## Prerequisites and setup

| Requirement | Needed for |
|---|---|
| Python 3.12.x (the project's virtual environment uses 3.12) | everything |
| `git` | fallback (`GitTool`) |
| [GitHub CLI](https://cli.github.com/) (`gh`), logged in | fallback issue creation |
| `pip install -r requirements.txt` (`google-adk[mcp,eval]>=2.12.0`) | everything: `workflow.py` imports ADK and the MCP client on startup, even for the fallback |
| `GOOGLE_API_KEY=<your-gemini-api-key>` | MCP path (Gemini agents) |
| `GITHUB_TOKEN=<your-github-token>` | MCP path (GitHub MCP server) |
| A local clone of the repository being reviewed | fallback (`--repo-path`) |

The fallback does not need `GOOGLE_API_KEY` or `GITHUB_TOKEN`; it uses your `gh` login.

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `GOOGLE_API_KEY` | Gemini API key (MCP path) | none |
| `GITHUB_TOKEN` | GitHub token for the MCP server (MCP path) | none |
| `GITHUB_MCP_URL` | Overrides the MCP server URL | `https://api.githubcopilot.com/mcp/` |
| `SECURITY_REVIEW_FORCE_FALLBACK` | `1`, `true`, `yes` or `on` forces the fallback | off |
| `SECURITY_REVIEW_REPO_PATH` | Local clone path for the fallback (same as `--repo-path`) | none |
| `SECURITY_REVIEW_AUDIT_LOG` | Audit log file path | `security_reviewer_audit.jsonl` in the working directory |
| `ADK_ENABLE_CONFIRMATION` | Set to `0` to skip the ADK confirmation pause on the MCP path | enabled |

Never commit real credentials. Copy `.env.example` to `.env` (it is git-ignored) for the MCP-path keys, which `adk web` loads automatically. For `python -m workflow`, export them in your shell.

### Install

```bash
# macOS / Linux
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export GOOGLE_API_KEY="<your-gemini-api-key>"     # MCP path only
export GITHUB_TOKEN="<your-github-token>"         # MCP path only
```

```powershell
# Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

$env:GOOGLE_API_KEY = "<your-gemini-api-key>"     # MCP path only
$env:GITHUB_TOKEN   = "<your-github-token>"       # MCP path only
```

Authenticate the GitHub CLI (needed for fallback issue creation):

```bash
gh auth login
gh auth status
```

## How to run

Run from the project folder (the one containing `workflow.py`).

```text
python -m workflow --repo <owner/repo> --commit <sha> [--decision approve|reject|interactive] [--repo-path <local clone>]
```

| Option | Meaning |
|---|---|
| `--repo` | GitHub repository in `owner/repo` form. Required. |
| `--commit` | Commit SHA. Required. The fallback accepts a hex SHA of 4–64 characters (not a branch name or `HEAD`). |
| `--decision` | `interactive` (default, prompts y/N), `approve` or `reject` (scripted decision). |
| `--repo-path` | Local clone, used only by the fallback. Can also be set with `SECURITY_REVIEW_REPO_PATH`. |

### MCP path (used when MCP is reachable)

```bash
# Interactive terminal prompt (asks y/N when SummaryDecisionAgent pauses):
python -m workflow --repo owner/repo --commit <commit_sha>

# Simulate Human Approval (creates GitHub issue via MCP):
python -m workflow --repo owner/repo --commit <commit_sha> --decision approve

# Simulate Human Rejection (skips issue creation and outputs brief summary):
python -m workflow --repo owner/repo --commit <commit_sha> --decision reject
```

### Local fallback path

```bash
# macOS / Linux: force the fallback
SECURITY_REVIEW_FORCE_FALLBACK=1 python -m workflow --repo owner/repo --commit <commit_sha> --repo-path <path-to-local-clone>
```

```powershell
# Windows PowerShell: force the fallback
$env:SECURITY_REVIEW_FORCE_FALLBACK = "1"
python -m workflow --repo owner/repo --commit <commit_sha> --repo-path <path-to-local-clone>
```

To trigger the fallback by simulating an MCP outage instead, leave the force switch unset and set `GITHUB_MCP_URL=http://127.0.0.1:9/`. The first lines of output state which path ran and why (`LOCAL FALLBACK` and `Reason: ...`).

### ADK Web UI (MCP path only)

```bash
adk web --log_level DEBUG
```

Sample prompt:

```text
Review repository <owner/repo> at commit <short_sha>.
When the review is complete, request approval to create a GitHub issue.
```

When the review reaches `SummaryDecisionAgent`, respond to ADK Web's confirmation request to approve or reject issue creation. The workflow resumes after that response. `adk web` and `adk eval` always use the MCP pipeline; MCP/fallback selection happens only in `python -m workflow`.

### Agent evaluation (MCP path)

Keep the imports unchanged and add the project directory to Python's import path when running eval. From the project folder:

```bash
pip install "google-adk[eval]"

PYTHONPATH="$PWD" adk eval . security_code_reviewer_eval_suite.evalset.json \
  --config_file_path=test_config.json \
  --print_detailed_results
```

## Testing

```bash
python -m unittest discover -s tests -v
```

Run it with the project's virtual environment active. The tests that exercise `workflow.py` and `tools.py` need the `mcp` package (installed by `requirements.txt`); without it they are skipped with a message. No test creates a real GitHub issue: `gh` is always mocked, while the Git tests use throw-away temporary repositories with fake secrets.

| Test file | What it covers |
|---|---|
| `tests/test_fetch_status.py` | Fetch-failure handling of the MCP pipeline |
| `tests/test_git_tool.py` | `GitTool`: valid and short commit, invalid commit/repository, timeout and single retry, read-only behavior, truncation, no secrets in errors or logs |
| `tests/test_scanner_tool.py` | `ScannerTool`: password, API key/token and unsafe-configuration rules, clean diff, multiple findings, removed lines ignored, file/line extraction, environment-variable lookups not flagged, empty/invalid input, complete redaction |
| `tests/test_github_issue_tool.py` | `GitHubIssueTool`: approval required, token and payload validation, unredacted-secret blocking, the exact `gh` command, returned URL/number, CLI failure, timeout, no retry, no secrets in body/result/errors/logs |
| `tests/test_fallback_pipeline.py` | End-to-end fallback (Git → scanner → approval → issue): YES creates exactly one issue, NO creates none, a clean commit asks for no approval, Git/scanner/`gh` failures stop safely, no retry, audit trail contents and redaction, MCP/fallback selection, MCP URL override, `workflow.py` wiring |

## Audit logging

Each run writes a step-by-step trail as **JSON Lines** (one JSON object per line) to `security_reviewer_audit.jsonl` in the working directory, or to the file named by `SECURITY_REVIEW_AUDIT_LOG`. Each event is also written to `security_reviewer.log` through the existing `configure_logging()` setup, as a line containing `AUDIT`. `*.jsonl` and `*.log` are git-ignored.

**Events (fallback path):**

| Action | Tool | Recorded when |
|---|---|---|
| `backend_selected` | `selector` | The MCP/fallback decision, with the reason |
| `workflow_started` | `pipeline` | The fallback review begins |
| `git_show` | `GitTool` | Commit fetched, or the error code |
| `security_scan` | `ScannerTool` | Scan finished (finding count), or the error code |
| `diagnosis` | `pipeline` | Risk level decided, or "no findings" (skipped) |
| `human_approval` | `approver` | The decision (`approved` or `rejected`) |
| `create_github_issue` | `GitHubIssueTool` | Success with issue number and URL, or the error code |
| `workflow_completed` | `pipeline` | Final status |

The MCP path records `backend_selected`, `human_approval` and `workflow_completed`.

**Fields:** `timestamp` (UTC), `run_id`, `step`, `action`, `tool`, `reason`, `repository`, `commit_id`, `backend` (`fallback` or `mcp`), `outcome`, `approval_decision`, `issue_number`, `issue_url`, `error_code`, `details`.

**Never logged:** raw diffs, evidence, issue bodies, complete passwords, API keys, tokens or credentials. Values are redacted and size-limited, and keys such as `diff`, `evidence`, `body`, `token`, `password` and `authorization` are dropped. A failure to write the audit file never stops a review.

Sanitized example (one line in the file, formatted here for reading):

```json
{
  "timestamp": "2025-01-01T10:00:00.000000+00:00",
  "run_id": "0123456789ab",
  "step": 6,
  "action": "human_approval",
  "tool": "approver",
  "reason": "Ask the human to approve issue creation",
  "repository": "<owner>/<demo-repo>",
  "commit_id": "<full-commit-sha>",
  "backend": "fallback",
  "outcome": "success",
  "approval_decision": "approved",
  "issue_number": null,
  "issue_url": null,
  "error_code": null,
  "details": {}
}
```

## Demo scenario

> **Warning:** use only a controlled demo repository containing **fake** credentials (for example `API_KEY = "sk_test_FAKE..."`). Never run the demo against a production repository or with real secrets. Approving creates a **real** GitHub issue in the target repository.

The setup scripts (`setup.sh` for Bash, `setup.ps1` for PowerShell) set the demo values and add short `demo_*` commands. Edit the defaults at the top of the script, or set the variable before loading it:

| Variable | Meaning |
|---|---|
| `repo` | GitHub `owner/repo` of the demo repository (receives the issue) |
| `demo` | Local clone of the demo repository |
| `sha` | Commit that contains the fake secret |
| `clean_sha` | Commit with no secrets |

**One-time preparation:** the demo repository has Issues enabled, you have a local clone, one commit adds a fake secret, another commit has none, the project dependencies are installed (see [Install](#install)), and `gh auth login` is done.

**Load the demo values and commands** (from the project folder):

```bash
# Git Bash / macOS / Linux
source ./setup.sh
```

```powershell
# Windows PowerShell
. .\setup.ps1
```

**Demo sequence:**

| # | Command | What the panel sees |
|---|---|---|
| 1 | `demo_check` | Tool versions, `gh` login status, the demo commits |
| 2 | `demo_clean` | Clean commit: `No security issue found; no GitHub issue was created.` No approval prompt. |
| 3 | `demo_reject` | The fake key is detected: `HIGH API_KEY_OR_TOKEN at <file>:<line> -> API_KEY = "[REDACTED]"`. The human decision is NO: `Human did not approve; no GitHub issue was created.` |
| 4 | `demo_mcp_down` | MCP is made unreachable (`GITHUB_MCP_URL` points at a dead address). The run reports `Reason: GitHub MCP server is unreachable` and continues on the fallback. |
| 5 | `demo_interactive` | Same findings; **you** type `y` at `Approve creating GitHub Issue in repo? [y/N]`. This creates one real issue, and the output shows the issue number and URL. (`demo_approve` does the same with a scripted YES, after asking you to type `create`.) |
| 6 | `demo_issues` | The new issue is listed on GitHub. Open it to show that the body has severity, file, line, `[REDACTED]` evidence and the recommendation, and no secret. |
| 7 | `demo_audit` | A table of the run's audit events: selection → git → scan → diagnosis → approval → issue creation (with the issue URL) → completed. |
| 8 | `demo_verify` | `OK: no secret and no raw diff in <audit log>` |
| 9 | `demo_reset` | Removes the audit file. Close the demo issue with `gh issue close <N> --repo <owner/repo>`. |

Optional failure demo: run step 5 *before* `gh auth login`. The run stops with `GitHub authentication failed`, creates no issue and makes exactly one attempt.

Each `demo_*` command runs `python -m workflow --repo <repo> --commit <sha> --repo-path <demo>` with the options described in [How to run](#how-to-run). `demo_clean`, `demo_reject` and `demo_mcp_down` use `--decision reject`, so they can never create an issue. Run step 5 only once: each approved run creates another issue, because the tool does not detect duplicates.

## Known limitations

- **Limited rules.** The scanner has four regex rules (three finding types). It matches on variable names such as `password` or `api_key`, so a secret with an unrelated name is not reported, and some harmless assignments may be flagged.
- **Line-by-line scanning.** Multi-line values and secrets built from several strings are not detected. Lines longer than 2,000 characters are skipped and counted. Diffs larger than 1,000,000 characters are truncated.
- **Config formats.** Unquoted values (for example `DB_PASSWORD=abc`) are treated as literals only in `.env*`, `.ini`, `.cfg`, `.conf`, `.properties`, `.yml`, `.yaml` and `.toml` files. In code, only quoted values count. Merge-commit diffs (`diff --cc`) are not scanned for added lines.
- **Fallback needs a local clone and `gh`.** The repository is read from `--repo-path` (or `SECURITY_REVIEW_REPO_PATH`), and the commit must be a hex SHA. Issue creation needs `gh` installed and logged in.
- **Selection is a single probe at startup.** It sends no credentials, so a reachable MCP server with a missing or invalid `GITHUB_TOKEN` still selects the MCP path, and an MCP failure in the middle of a run does not switch to the fallback. Use `SECURITY_REVIEW_FORCE_FALLBACK=1` to be certain. Selection happens only in `python -m workflow`; `adk web` and `adk eval` use MCP only.
- **The fallback report is rule-based.** There is no LLM-written analysis in the fallback; the issue is a structured findings list. The MCP path audit log has no issue number or URL (the agent creates that issue through the LLM).
- **Approval.** The fallback approval is a terminal prompt. The approval token is an integrity check, not a signature, and approvals are not single-use. There is no duplicate-issue detection, and no retry after a failure or timeout.
- **Audit log.** It is append-only with no rotation; concurrent runs share the file and are told apart by `run_id`.
- **Tests do not call GitHub.** They mock `gh`, so the first real issue creation is verified by the demo.

## Project structure

```text
.
├── workflow.py                      # CLI entry point: path selection, MCP loop, fallback runner
├── agent.py                         # SequentialAgent pipeline + resumable App (MCP path)
├── repo_fetch_agent.py              # MCP path: fetch commit via GitHub MCP
├── security_review_agent.py         # MCP path: LLM security review
├── summary_decision_agent.py        # MCP path: human approval request
├── issue_report_agent.py            # MCP path: create issue via MCP
├── fetch_status.py                  # MCP path: stop on failed fetch
├── tools.py                         # MCP toolsets + request_security_issue_approval
├── observability.py                 # security_reviewer.log + metrics plugin
├── fallback/                        # Local functional-tool fallback
│   ├── selection.py                 #   MCP vs fallback choice, MCP URL override
│   ├── pipeline.py                  #   Git -> scanner -> approval -> issue flow
│   ├── git_tool.py                  #   GitTool
│   ├── scanner_tool.py              #   ScannerTool
│   ├── github_issue_tool.py         #   GitHubIssueTool
│   ├── audit.py                     #   JSONL audit logger
│   └── result.py                    #   result contract + redaction
├── tests/                           # unittest suite (see Testing)
├── setup.sh / setup.ps1             # demo setup scripts (Bash / PowerShell)
├── security_code_reviewer_eval_suite.evalset.json, security_reviewer.test.json, test_config.json
│                                    # ADK evaluation data and thresholds (MCP path)
├── requirements.txt
└── .env.example
```

### MCP path file notes

- `repo_fetch_agent.py`: Defines `repo_fetch_agent()` with read-only GitHub MCP (`output_key="commit_code_details"`).
- `security_review_agent.py`: Defines `security_review_agent()` reading `{commit_code_details}` (`output_key="security_analysis_report"`).
- `summary_decision_agent.py`: Defines `summary_decision_agent()` reading `{security_analysis_report}` and calling `request_security_issue_approval` (`output_key="summary_decision_output"`).
- `issue_report_agent.py`: Defines `issue_report_agent()` reading `{security_analysis_report}` and `{summary_decision_output}` to create a GitHub issue via MCP if approved or summarize if rejected (`output_key="final_issue_or_summary"`).
- `agent.py`: Composes the 4 agents into `root_agent` (`SequentialAgent`) and wraps them in `security_review_app` (`App` with `ResumabilityConfig(is_resumable=True)`).
- `tools.py`: Configures `McpToolset` with `StreamableHTTPServerParams` for the GitHub MCP server (`https://api.githubcopilot.com/mcp/` unless `GITHUB_MCP_URL` is set) and implements the `request_security_issue_approval` Human-in-the-Loop tool using `ToolContext.request_confirmation()`.
- `workflow.py`: Chooses MCP or the local fallback (`select_backend()`), then either runs the stateful session and LRO execution loop using `InMemorySessionService`, `Runner`, `check_for_approval()`, and `create_approval_response()` (MCP path) or `run_fallback_workflow()` (fallback path).
- `observability.py`: Configures `security_reviewer.log` (`DEBUG` level) and combines ADK's `LoggingPlugin()` with a custom `SecurityReviewObservabilityPlugin(BasePlugin)`. Audit events are also written to this log.
- `test_config.json`, `security_code_reviewer_eval_suite.evalset.json`, `security_reviewer.test.json`: Agent evaluation test suites and thresholds (`tool_trajectory_avg_score` & `response_match_score`).
