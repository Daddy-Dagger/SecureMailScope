# SecureMailScope — Beginner-Friendly Checkpoint Script (Windows PowerShell)
# Usage: .\scripts\checkpoint.ps1 "message"

[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory=$false)]
    [string]$Message
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Message)) {
    Write-Host "Error: Missing checkpoint commit message." -ForegroundColor Red
    Write-Host "Usage: .\scripts\checkpoint.ps1 `"what you worked on`""
    exit 1
}

# 1. Ensure inside git repository
try {
    $insideGit = git rev-parse --is-inside-work-tree 2>$null
    if ($LASTEXITCODE -ne 0 -or $insideGit -ne "true") {
        Write-Host "Error: Not inside a Git repository." -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "Error: Not inside a Git repository." -ForegroundColor Red
    exit 1
}

# 2. Detect the current Git branch
$branch = git branch --show-current 2>$null
if (-not $branch) {
    $branch = git rev-parse --abbrev-ref HEAD 2>$null
}
if ($branch) {
    $branch = $branch.Trim()
}

if (-not $branch -or $branch -eq "HEAD") {
    Write-Host "Error: You are in a 'detached HEAD' state (not on any branch)." -ForegroundColor Red
    Write-Host "Please switch to your assigned member branch first, for example:"
    Write-Host "  git checkout lead/core-engine"
    exit 1
}

# 3. Refuse to run on main or develop
if ($branch -eq "main" -or $branch -eq "develop") {
    Write-Host "Error: Checkpoints cannot be run directly on '$branch'." -ForegroundColor Red
    Write-Host "Safety rule: All work must take place on your assigned member branch (e.g., lead/core-engine, memberX/...)."
    Write-Host "Please switch to your member branch and try again:"
    Write-Host "  git checkout <your-branch>"
    exit 1
}

# 4. Refuse to run if a merge, rebase, or unresolved conflict is active
$gitDir = (git rev-parse --git-dir 2>$null).Trim()
if ((Test-Path (Join-Path $gitDir "MERGE_HEAD")) -or
    (Test-Path (Join-Path $gitDir "rebase-merge")) -or
    (Test-Path (Join-Path $gitDir "rebase-apply")) -or
    (Test-Path (Join-Path $gitDir "CHERRY_PICK_HEAD")) -or
    (Test-Path (Join-Path $gitDir "REVERT_HEAD"))) {
    Write-Host "Error: A Git merge, rebase, or cherry-pick operation is currently in progress." -ForegroundColor Red
    Write-Host "Please resolve or abort that operation before making a checkpoint."
    exit 1
}

$unmerged = git diff --name-only --diff-filter=U 2>$null
if ($unmerged) {
    Write-Host "Error: Unresolved merge conflicts detected in the following files:" -ForegroundColor Red
    $unmerged | ForEach-Object { Write-Host "  $_" }
    Write-Host "Please resolve all conflicts before checkpointing."
    exit 1
}

# 5. Check if there are changes to commit
$statusOutput = git status --porcelain 2>$null
if (-not $statusOutput) {
    Write-Host "No changes to checkpoint."
    exit 0
}

# 6. Stage all changes
git add -A
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to stage changes with git add -A." -ForegroundColor Red
    exit 1
}

# 7. Commit with sanitized wip(<branch>): <message> format
$cleanBranch = $branch.Trim()
$commitMsg = "wip(${cleanBranch}): $Message"

git commit -m $commitMsg
if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Failed to create git commit." -ForegroundColor Red
    exit 1
}

$hash = (git rev-parse --short HEAD 2>$null).Trim()

# 8. Push to the current branch (never force push)
$hasUpstream = $false
git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>$null | Out-Null
if ($LASTEXITCODE -eq 0) {
    $hasUpstream = $true
}

if ($hasUpstream) {
    git push
} else {
    git push -u origin $branch
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "Error: Push to remote failed." -ForegroundColor Red
    Write-Host "Please check your network connection or remote branch permissions."
    Write-Host "Note: Never force-push."
    exit 1
}

# 9. Print completion message
Write-Host ""
Write-Host "Checkpoint complete."
Write-Host "Branch: $branch"
Write-Host "Commit: $hash"
Write-Host "Draft PR automatically reflects this push if one exists."
