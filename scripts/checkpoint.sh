#!/usr/bin/env bash
set -euo pipefail

# SecureMailScope — Beginner-Friendly Checkpoint Script (macOS / Linux)
# Usage: ./scripts/checkpoint.sh "message"

if [ $# -lt 1 ] || [ -z "${1-}" ]; then
  echo "Error: Missing checkpoint commit message."
  echo "Usage: ./scripts/checkpoint.sh \"what you worked on\""
  exit 1
fi

COMMIT_DESC="$1"

# 1. Ensure we are in a git repository
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "Error: Not inside a Git repository."
  exit 1
fi

# 2. Detect the current Git branch
BRANCH="$(git branch --show-current 2>/dev/null || git rev-parse --abbrev-ref HEAD 2>/dev/null)"
if [ -z "$BRANCH" ] || [ "$BRANCH" = "HEAD" ]; then
  echo "Error: You are in a 'detached HEAD' state (not on any branch)."
  echo "Please switch to your assigned member branch first, for example:"
  echo "  git checkout lead/core-engine"
  exit 1
fi

# 3. Refuse to run on protected integration and release branches
if [ "$BRANCH" = "main" ] || [ "$BRANCH" = "develop" ]; then
  echo "Error: Checkpoints cannot be run directly on '$BRANCH'."
  echo "Safety rule: All work must take place on your assigned member branch (e.g., lead/core-engine, memberX/...)."
  echo "Please switch to your member branch and try again:"
  echo "  git checkout <your-branch>"
  exit 1
fi

# 4. Refuse to run if a merge, rebase, or unresolved conflict is active
GIT_DIR="$(git rev-parse --git-dir)"
if [ -f "$GIT_DIR/MERGE_HEAD" ] || [ -d "$GIT_DIR/rebase-merge" ] || [ -d "$GIT_DIR/rebase-apply" ] || [ -f "$GIT_DIR/CHERRY_PICK_HEAD" ] || [ -f "$GIT_DIR/REVERT_HEAD" ]; then
  echo "Error: A Git merge, rebase, or cherry-pick operation is currently in progress."
  echo "Please resolve or abort that operation before making a checkpoint."
  exit 1
fi

UNMERGED="$(git diff --name-only --diff-filter=U 2>/dev/null || true)"
if [ -n "$UNMERGED" ]; then
  echo "Error: Unresolved merge conflicts detected in the following files:"
  echo "$UNMERGED"
  echo "Please resolve all conflicts before checkpointing."
  exit 1
fi

# 5. Check if there are changes to commit
STATUS_OUTPUT="$(git status --porcelain)"
if [ -z "$STATUS_OUTPUT" ]; then
  echo "No changes to checkpoint."
  exit 0
fi

# 6. Stage all changes
git add -A

# 7. Commit with sanitized wip(<branch>): <message> format
CLEAN_BRANCH="$(echo "$BRANCH" | tr -d '\r\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
COMMIT_MSG="wip(${CLEAN_BRANCH}): ${COMMIT_DESC}"

git commit -m "$COMMIT_MSG"
HASH="$(git rev-parse --short HEAD)"

# 8. Push to the current branch (never force push)
if git rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
  git push
else
  git push -u origin "$BRANCH"
fi

# 9. Print completion message
echo ""
echo "Checkpoint complete."
echo "Branch: ${BRANCH}"
echo "Commit: ${HASH}"
echo "Draft PR automatically reflects this push if one exists."
