"""Fallback review pipeline: GitTool -> ScannerTool -> diagnosis -> human approval -> GitHubIssueTool.

Runs without MCP and without an LLM. The raw diff only travels from GitTool to ScannerTool
inside this module; the returned result and the audit log contain redacted findings only.
"""

from typing import Callable, Optional

from fallback.audit import AuditLogger
from fallback.git_tool import GitTool
from fallback.github_issue_tool import GitHubIssueTool, compute_approval_token
from fallback.result import fail, redact_text
from fallback.scanner_tool import ScannerTool

BACKEND = "fallback"
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Receives the (redacted) approval request and returns True only for an explicit YES.
Approver = Callable[[dict], bool]


def cli_approver(auto_approve: Optional[bool] = None) -> Approver:
    """Same decision options as the existing CLI: prompt y/N, or --decision approve/reject."""

    def approve(request: dict) -> bool:
        print(f"\n{'-' * 70}")
        print("WORKFLOW PAUSED FOR HUMAN CONFIRMATION")
        print(request["hint"])
        print(f"{'-' * 70}")
        if auto_approve is None:
            answer = input("\nApprove creating GitHub Issue in repo? [y/N]: ").strip().lower()
            return answer in ("y", "yes")
        print(f"Simulated Human Decision: {'APPROVE' if auto_approve else 'REJECT'}")
        return auto_approve

    return approve


def run_fallback_review(
    repo_name: str,
    repo_path: str,
    commit_id: str,
    approver: Approver,
    *,
    git_tool: Optional[GitTool] = None,
    scanner_tool: Optional[ScannerTool] = None,
    issue_tool: Optional[GitHubIssueTool] = None,
    audit: Optional[AuditLogger] = None,
    selection_reason: str = "fallback selected",
) -> dict:
    """Runs the whole fallback flow and returns {"success", "summary", "data", "error"}.

    repo_name is the GitHub "owner/repo" used for the issue; repo_path is the local clone.
    data["status"] is one of: FETCH_FAILED, SCAN_FAILED, CLEAN, REJECTED, ISSUE_CREATED,
    ISSUE_FAILED. Only ISSUE_CREATED means an issue exists.
    """
    git_tool = git_tool or GitTool()
    scanner_tool = scanner_tool or ScannerTool()
    issue_tool = issue_tool or GitHubIssueTool()
    audit = audit or AuditLogger()
    context = {"repository": repo_name, "commit_id": commit_id, "backend": BACKEND}

    def log(action, tool, reason, outcome, **extra):
        audit.record(action, tool, reason, outcome, **context, **extra)

    def finish(status, success, summary, *, findings=None, approval="not_requested",
               issue=None, error=None, risk_level=None):
        findings = findings or []
        log(
            "workflow_completed", "pipeline", "Fallback review finished",
            "success" if success else "failure",
            approval_decision=approval if approval != "not_requested" else None,
            issue_number=issue["issue_number"] if issue else None,
            issue_url=issue["issue_url"] if issue else None,
            error_code=error["code"] if error else None,
            details={"status": status, "finding_count": len(findings)},
        )
        return {
            "success": success,
            "summary": redact_text(summary),
            "data": {
                "status": status,
                "backend": BACKEND,
                "repository": repo_name,
                "commit_id": context["commit_id"],
                "risk_level": risk_level,
                "finding_count": len(findings),
                "findings": findings,
                "approval": approval,
                "issue": issue,
                "audit_run_id": audit.run_id,
            },
            "error": error,
        }

    log("workflow_started", "pipeline",
        "Review the commit with the local fallback tools (GitTool -> ScannerTool -> approval -> GitHubIssueTool)",
        "started", details={"selection_reason": selection_reason})

    # 1. GitTool: fetch the diff. A failure stops everything.
    git_result = _call(git_tool.run, repo_path, commit_id)
    if not git_result["success"]:
        log("git_show", "GitTool", "Fetch the commit diff from the local repository", "failure",
            error_code=git_result["error"]["code"])
        return finish("FETCH_FAILED", False, f"Could not read the commit. {git_result['summary']}",
                      error=git_result["error"])
    git_data = git_result["data"]
    context["commit_id"] = git_data["commit_id"]
    log("git_show", "GitTool", "Fetch the commit diff from the local repository", "success",
        details={"changed_files": len(git_data["changed_files"]), "truncated": git_data["truncated"]})

    # 2. ScannerTool: the raw diff is used here and nowhere else.
    scan_result = _call(scanner_tool.run, git_data["diff"])
    git_data = None
    if not scan_result["success"]:
        log("security_scan", "ScannerTool", "Scan added lines for secrets and unsafe configuration",
            "failure", error_code=scan_result["error"]["code"])
        return finish("SCAN_FAILED", False, f"Could not scan the commit. {scan_result['summary']}",
                      error=scan_result["error"])
    findings = scan_result["data"]["findings"]
    log("security_scan", "ScannerTool", "Scan added lines for secrets and unsafe configuration", "success",
        details={"finding_count": len(findings), "lines_scanned": scan_result["data"]["lines_scanned"]})

    # 3. Diagnosis: a clean commit stops here, without approval or an issue.
    if not findings:
        log("diagnosis", "pipeline", "Decide whether the commit needs an issue", "skipped",
            details={"result": "no findings"})
        return finish("CLEAN", True, "No security issue found; no GitHub issue was created.")
    risk_level = next(sev for sev in SEVERITY_ORDER if any(f["severity"] == sev for f in findings))
    title = f"[Security] {risk_level}: {len(findings)} finding(s) in commit {context['commit_id'][:7]}"
    log("diagnosis", "pipeline", "Decide whether the commit needs an issue", "success",
        details={"risk_level": risk_level, "finding_count": len(findings)})

    # 4. Human approval. Anything other than an explicit True means NO.
    request = {
        "repo_name": repo_name,
        "commit_id": context["commit_id"],
        "issue_title": title,
        "severity_summary": f"{len(findings)} finding(s), highest severity {risk_level}.",
        "findings": findings,
        "hint": _approval_hint(repo_name, context["commit_id"], title, findings),
    }
    try:
        approved = approver(request) is True
    except Exception as exc:  # fail closed: an approver error is never a YES
        approved = False
        log("human_approval", "approver", "Ask the human to approve issue creation", "failure",
            approval_decision="rejected", error_code=type(exc).__name__)
    else:
        log("human_approval", "approver", "Ask the human to approve issue creation", "success",
            approval_decision="approved" if approved else "rejected")
    if not approved:
        return finish("REJECTED", True, "Human did not approve; no GitHub issue was created.",
                      findings=findings, approval="rejected", risk_level=risk_level)

    # 5. GitHubIssueTool: called once, only after YES. The token binds the approval to this content.
    payload = {
        "repository": repo_name,
        "commit_id": context["commit_id"],
        "title": title,
        "findings": findings,
        "approval": {
            "status": "approved",
            "token": compute_approval_token(repo_name, context["commit_id"], title, findings),
        },
    }
    issue_result = _call(issue_tool.run, payload)
    if not issue_result["success"]:
        log("create_github_issue", "GitHubIssueTool", "Create the approved GitHub issue (no retry)",
            "failure", approval_decision="approved", error_code=issue_result["error"]["code"])
        return finish("ISSUE_FAILED", False, f"GitHub issue was not created. {issue_result['summary']}",
                      findings=findings, approval="approved", error=issue_result["error"],
                      risk_level=risk_level)
    issue = {
        "issue_number": issue_result["data"]["issue_number"],
        "issue_url": issue_result["data"]["issue_url"],
    }
    log("create_github_issue", "GitHubIssueTool", "Create the approved GitHub issue (no retry)", "success",
        approval_decision="approved", issue_number=issue["issue_number"], issue_url=issue["issue_url"])
    return finish("ISSUE_CREATED", True, issue_result["summary"], findings=findings,
                  approval="approved", issue=issue, risk_level=risk_level)


def _call(tool_run, *args) -> dict:
    """Runs a tool and turns an unexpected exception into a structured error."""
    try:
        return tool_run(*args)
    except Exception as exc:  # never include exc text: it could contain sensitive content
        return fail("TOOL_CRASHED", f"Tool crashed: {type(exc).__name__}.", "A tool failed unexpectedly.")


def _approval_hint(repo_name: str, commit_id: str, title: str, findings: list) -> str:
    lines = [
        f"Security review completed for {repo_name} @ {commit_id}.",
        f"Proposed Issue: {title}",
    ]
    for finding in findings:
        lines.append(
            f"  - {finding['severity']} {finding['type']} at {finding['file']}:{finding['line']} "
            f"-> {finding['evidence']}"
        )
    lines.append(f"Do you approve creating this GitHub issue in {repo_name}?")
    return "\n".join(lines)
