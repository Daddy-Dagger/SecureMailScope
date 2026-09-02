#!/usr/bin/env bash
set -eo pipefail

# SecureMailScope — Team Status Script (macOS / Linux)
# Usage: ./scripts/team-status.sh

# 1. Fetch remote tracking updates
echo "Fetching updates from origin..."
git fetch origin 2>/dev/null || echo "Notice: Could not fetch from 'origin' (working offline or remote unreachable)."

# 2. Show current branch
CURRENT_BRANCH="$(git branch --show-current 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null)"
echo ""
echo "=== Current Branch ==="
echo "${CURRENT_BRANCH}"

# Show git status
echo ""
echo "=== Git Working Tree Status ==="
git status

# Show remote member branches
echo ""
echo "=== Remote Member Branches ==="
git branch -r --list 'origin/lead/*' 'origin/member*' 2>/dev/null || git branch -r

# 3. Check GitHub CLI availability and authentication
echo ""
echo "=== Active Pull Requests (develop) ==="
if command -v gh >/dev/null 2>&1 && gh auth status >/dev/null 2>&1; then
  gh pr list --base develop --state open
else
  echo "GitHub CLI not available; branch status shown only."
fi
