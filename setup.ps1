# Demo setup for the Security Commit Reviewer (Windows PowerShell / PowerShell 7).
#
#   . .\setup.ps1        <- dot-source it so the values and demo_* commands stay in your session
#
# Bash users: use  source ./setup.sh  instead.
# Any value below can be overridden by setting the variable before you dot-source this file.
# Only fake credentials may exist in the demo repository.

Set-Location $PSScriptRoot

if (-not $py) {
    $py = if (Test-Path .\.venv\Scripts\python.exe) { ".\.venv\Scripts\python.exe" }
          elseif (Test-Path ./.venv/bin/python) { "./.venv/bin/python" }
          else { "python" }                                        # python used to run the reviewer
}
if (-not $demo)      { $demo      = "..\agentic-ai-demo-repo" }          # LOCAL clone of the demo repo
if (-not $repo)      { $repo      = "Priyankaj022/agentic-ai-demo-repo" } # GitHub owner/repo that receives the issue
if (-not $sha)       { $sha       = "f877d0d" }                          # commit that contains the fake API_KEY
if (-not $clean_sha) { $clean_sha = "582e7be" }                          # commit with no secrets
if (-not $demo_secret_fragment) { $demo_secret_fragment = "FAKE1234567890" }  # used only to prove the fake key is never logged
if (-not $env:SECURITY_REVIEW_AUDIT_LOG) { $env:SECURITY_REVIEW_AUDIT_LOG = Join-Path $PSScriptRoot "demo_audit.jsonl" }

# Runs the reviewer with temporary environment variables, then restores them.
# A $null value removes the variable for the duration of the run.
function Invoke-DemoWorkflow {
    param([string]$Commit, [string[]]$Extra = @(), [hashtable]$EnvVars = @{ SECURITY_REVIEW_FORCE_FALLBACK = "1" })
    $saved = @{}
    foreach ($name in $EnvVars.Keys) {
        $saved[$name] = [Environment]::GetEnvironmentVariable($name)
        [Environment]::SetEnvironmentVariable($name, $EnvVars[$name])
    }
    try { & $py -W ignore -m workflow --repo $repo --commit $Commit --repo-path $demo @Extra }
    finally { foreach ($name in $saved.Keys) { [Environment]::SetEnvironmentVariable($name, $saved[$name]) } }
}

function demo_check {
    Write-Host "Tools:"; git --version; & $py --version; $env:GH_PROMPT_DISABLED = "1"; gh --version | Select-Object -First 1
    gh auth status *> $null
    if ($LASTEXITCODE -eq 0) { "gh: logged in" } else { "gh: NOT logged in (run: gh auth login)" }
    Write-Host "Demo repo ($demo):"; git -C $demo log --oneline -3
    "Target repo: $repo | Audit log: $env:SECURITY_REVIEW_AUDIT_LOG"
}
function demo_clean       { Invoke-DemoWorkflow $clean_sha @("--decision", "reject") }  # clean commit: no approval, no issue
function demo_reject      { Invoke-DemoWorkflow $sha @("--decision", "reject") }        # secret found, human says NO: no issue
function demo_interactive { Invoke-DemoWorkflow $sha }                                  # secret found, YOU answer y/N

function demo_approve {   # scripted YES. Creates a REAL issue, so it asks first.
    Write-Host "This will create a REAL GitHub issue in $repo."
    $answer = Read-Host "Type 'create' to continue"
    if ($answer -ne "create") { "Cancelled. Nothing was created."; return }
    Invoke-DemoWorkflow $sha @("--decision", "approve")
}

function demo_mcp_down {  # no force switch: MCP URL points at a dead address, so the fallback is chosen automatically
    Invoke-DemoWorkflow $sha @("--decision", "reject") @{ SECURITY_REVIEW_FORCE_FALLBACK = $null; GITHUB_MCP_URL = "http://127.0.0.1:9/" }
}

function demo_issues { $env:GH_PROMPT_DISABLED = "1"; gh issue list --repo $repo }

function demo_audit {     # prints the audit trail of the most recent run as a table
    $events = @(Get-Content $env:SECURITY_REVIEW_AUDIT_LOG | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
    $last = $events[-1].run_id
    $events | Where-Object { $_.run_id -eq $last } |
        Select-Object step, action, tool, outcome, approval_decision, issue_number, issue_url | Format-Table -AutoSize
}

function demo_verify {    # proves the fake secret and raw diffs are not in the audit log
    $hits = Select-String -Path $env:SECURITY_REVIEW_AUDIT_LOG -Pattern $demo_secret_fragment, "diff --git", "+++ b/" -SimpleMatch
    if ($hits) { "FAIL: sensitive content found in the audit log" }
    else { "OK: no secret and no raw diff in $env:SECURITY_REVIEW_AUDIT_LOG" }
}

function demo_reset { Remove-Item $env:SECURITY_REVIEW_AUDIT_LOG -ErrorAction SilentlyContinue; "Audit log removed." }

Write-Host "Demo values set:  repo=$repo  sha=$sha  clean_sha=$clean_sha"
Write-Host "                  demo=$demo"
Write-Host "                  audit=$env:SECURITY_REVIEW_AUDIT_LOG"
Write-Host "Commands: demo_check demo_clean demo_reject demo_mcp_down demo_interactive demo_approve demo_issues demo_audit demo_verify demo_reset"
