# SecureMailScope — Team Status Script (Windows PowerShell)
# Usage: .\scripts\team-status.ps1

Write-Host "Fetching updates from origin..."
try {
    git fetch origin 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Notice: Could not fetch from 'origin' (working offline or remote unreachable)."
    }
} catch {
    Write-Host "Notice: Could not fetch from 'origin' (working offline or remote unreachable)."
}

# Current branch
$branch = git branch --show-current 2>$null
if (-not $branch) {
    $branch = git rev-parse --abbrev-ref HEAD 2>$null
}
if ($branch) {
    $branch = $branch.Trim()
}

Write-Host ""
Write-Host "=== Current Branch ==="
Write-Host $branch

# Git status
Write-Host ""
Write-Host "=== Git Working Tree Status ==="
git status

# Remote member branches
Write-Host ""
Write-Host "=== Remote Member Branches ==="
$remoteBranches = git branch -r --list 'origin/lead/*' 'origin/member*' 2>$null
if (-not $remoteBranches) {
    $remoteBranches = git branch -r 2>$null
}
$remoteBranches | ForEach-Object { Write-Host $_ }

# Pull Requests check via gh
Write-Host ""
Write-Host "=== Active Pull Requests (develop) ==="
$ghCmd = Get-Command gh -ErrorAction SilentlyContinue
$ghAuthed = $false
if ($ghCmd) {
    $null = gh auth status 2>$null
    if ($LASTEXITCODE -eq 0) {
        $ghAuthed = $true
    }
}

if ($ghAuthed) {
    gh pr list --base develop --state open
} else {
    Write-Host "GitHub CLI not available; branch status shown only."
}
