#!/usr/bin/env bash
# Demo setup for the Security Commit Reviewer (Git Bash / WSL / Linux / macOS).
#
#   source ./setup.sh        <- "source" it so the values and demo_* commands stay in your shell
#
# PowerShell users: use  . .\setup.ps1  instead.
# Any value below can be overridden by exporting it before you source this file.
# Only fake credentials may exist in the demo repository.

(return 0 2>/dev/null) || { echo "Run this with:  source ./setup.sh"; exit 1; }

cd "$(dirname "${BASH_SOURCE[0]}")" || return 1

if [ -x ".venv/Scripts/python.exe" ]; then _default_py=".venv/Scripts/python.exe"   # Windows venv
elif [ -x ".venv/bin/python" ]; then _default_py=".venv/bin/python"                 # Linux/macOS venv
else _default_py="python"; fi

export py="${py:-$_default_py}"                              # python used to run the reviewer
export demo="${demo:-./../agentic-ai-demo-repo}"             # LOCAL clone of the demo repo
export repo="${repo:-Priyankaj022/agentic-ai-demo-repo}"     # GitHub owner/repo that receives the issue
export sha="${sha:-f877d0d}"                                 # commit that contains the fake API_KEY
export clean_sha="${clean_sha:-582e7be}"                     # commit with no secrets
export demo_secret_fragment="${demo_secret_fragment:-FAKE1234567890}"  # part of the fake key, used only to prove it is never logged
export SECURITY_REVIEW_AUDIT_LOG="${SECURITY_REVIEW_AUDIT_LOG:-$PWD/demo_audit.jsonl}"

# Runs the reviewer on the local fallback path (MCP is not contacted).
_demo_run() {   # usage: _demo_run <commit> [extra workflow options]
  local commit="$1"; shift
  SECURITY_REVIEW_FORCE_FALLBACK=1 "$py" -W ignore -m workflow \
    --repo "$repo" --commit "$commit" --repo-path "$demo" "$@"
}

demo_check()       { echo "Tools:"; git --version; "$py" --version; GH_PROMPT_DISABLED=1 gh --version | head -n 1
                     if GH_PROMPT_DISABLED=1 gh auth status >/dev/null 2>&1; then echo "gh: logged in"
                     else echo "gh: NOT logged in (run: gh auth login)"; fi
                     echo "Demo repo ($demo):"; git -C "$demo" log --oneline -3 || echo "NOT FOUND"
                     echo "Target repo: $repo | Audit log: $SECURITY_REVIEW_AUDIT_LOG"; }
demo_clean()       { _demo_run "$clean_sha" --decision reject; }     # clean commit: no approval, no issue
demo_reject()      { _demo_run "$sha" --decision reject; }           # secret found, human says NO: no issue
demo_interactive() { _demo_run "$sha"; }                             # secret found, YOU answer y/N

demo_approve() {   # scripted YES. Creates a REAL issue, so it asks first.
  echo "This will create a REAL GitHub issue in $repo."
  read -r -p "Type 'create' to continue: " _answer
  [ "$_answer" = "create" ] || { echo "Cancelled. Nothing was created."; return 1; }
  _demo_run "$sha" --decision approve
}

demo_mcp_down() {  # no force switch: MCP URL points at a dead address, so the fallback is chosen automatically
  env -u SECURITY_REVIEW_FORCE_FALLBACK GITHUB_MCP_URL="http://127.0.0.1:9/" \
    "$py" -W ignore -m workflow --repo "$repo" --commit "$sha" --repo-path "$demo" --decision reject
}

demo_issues()      { GH_PROMPT_DISABLED=1 gh issue list --repo "$repo"; }

demo_audit() {     # prints the audit trail of the most recent run as a table
  "$py" -c '
import json, sys
events = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
last = events[-1]["run_id"]
print("%-4s %-20s %-16s %-8s %-9s %s" % ("step", "action", "tool", "outcome", "approval", "issue"))
for e in events:
    if e["run_id"] == last:
        print("%-4s %-20s %-16s %-8s %-9s %s" % (e["step"], e["action"], e["tool"], e["outcome"],
              e["approval_decision"] or "-", e["issue_url"] or "-"))
' "$SECURITY_REVIEW_AUDIT_LOG"
}

demo_verify() {    # proves the fake secret and raw diffs are not in the audit log
  if grep -q -E "$demo_secret_fragment|diff --git|\+\+\+ b/" "$SECURITY_REVIEW_AUDIT_LOG"; then
    echo "FAIL: sensitive content found in the audit log"; return 1
  fi
  echo "OK: no secret and no raw diff in $SECURITY_REVIEW_AUDIT_LOG"
}

demo_reset()       { rm -f "$SECURITY_REVIEW_AUDIT_LOG"; echo "Audit log removed."; }

echo "Demo values set:  repo=$repo  sha=$sha  clean_sha=$clean_sha"
echo "                  demo=$demo"
echo "                  audit=$SECURITY_REVIEW_AUDIT_LOG"
echo "Commands: demo_check demo_clean demo_reject demo_mcp_down demo_interactive demo_approve demo_issues demo_audit demo_verify demo_reset"