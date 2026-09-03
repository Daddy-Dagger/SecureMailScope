# Agent Workflow

This workflow governs all coding agents (such as Codex, Antigravity, or other AI assistants) working inside the **SecureMailScope** repository.

## Workflow Lifecycle

```text
READ CONTEXT
      ↓
VERIFY REPOSITORY
      ↓
IMPLEMENT ONLY REQUESTED SCOPE
      ↓
TEST
      ↓
UPDATE PROJECT_CONTEXT
      ↓
REPORT RESULTS
```

---

## Workflow Steps

### 1. READ CONTEXT
- Read `docs/PROJECT_CONTEXT.md` completely before starting any work.
- Understand the current architecture, active milestone, boundaries, and team ownership model.
- Take note of ₹0 cost constraints, prototype focus, and technical guidelines.

### 2. VERIFY REPOSITORY
- Inspect the actual repository files, directories, and git status before making assumptions.
- Confirm whether referenced modules, contracts, or tests exist.
- Never rely solely on chat history or unverified assumptions.

### 3. IMPLEMENT ONLY REQUESTED SCOPE
- Work strictly on the assigned task or current milestone.
- Respect ownership boundaries defined in `docs/PROJECT_CONTEXT.md` and `.github/CODEOWNERS`.
- Do not implement future milestones prematurely.
- Do not make unilateral changes to shared contracts without lead coordination.
- Avoid introducing unnecessary libraries, cloud infrastructure, or complex automation.

### 4. TEST
- Run relevant unit, integration, and health tests (e.g., `python -m pytest`).
- Verify frontend builds if frontend files were modified (`npm run build` in `frontend/`).
- Confirm zero regressions in existing functionality.

### 5. UPDATE PROJECT_CONTEXT
- Review `docs/PROJECT_CONTEXT.md` and determine if project facts materially changed (e.g., structure, milestone status, contracts, dependencies, limitations).
- If state changed, update the relevant sections and add a dated entry to the **Context Update Log** (`YYYY-MM-DD — branch-name — concise description`).
- Never mark a feature implemented unless working code and verification exist.

### 6. REPORT RESULTS
- Report the canonical context path and files created or modified.
- Summarize verification results clearly.
- State whether `docs/PROJECT_CONTEXT.md` was updated or reviewed with no changes needed.

---

## Daily Member Flow

```text
DAILY MEMBER FLOW

READ CONTEXT
→ WORK ON ASSIGNED BRANCH
→ TEST
→ RUN CHECKPOINT SCRIPT
→ DRAFT PR UPDATES
→ CONTINUE WORK

WHEN READY

MARK PR READY
→ REVIEW
→ MERGE INTO develop
```

Do not create manual per-member status files for every small change.
Draft PRs are the live in-progress status.

---

## Mandatory Ending Instruction

Before finishing, update docs/PROJECT_CONTEXT.md if this task changed the real project state. If it did not, explicitly state that the file was reviewed and no update was required.

