# Contributing to SecureMailScope

## Branch strategy

- `main` — demo-ready, reviewed releases only
- `develop` — team integration branch
- `lead/core-engine` — core engine coordination
- `member2/pcap-lab` — PCAP loading and protocol lab work
- `member3/security-rules` — deterministic security rules
- `member4/backend-reports` — API and reporting
- `member5/frontend` — React interface
- `member6/testing-docs` — test coverage and documentation

Nobody pushes directly to `main`. Create feature work on the appropriate team branch, keep it focused, and open a Pull Request. Pull Requests merge into `develop` after review and passing tests. Only tested, demo-ready releases move from `develop` to `main`.

## Team Ownership and Conflict Prevention

To enable safe, concurrent collaboration across all 6 team members, work is organized around clear functional ownership boundaries:

### Ownership Table

| Area | Owner |
| --- | --- |
| `core/pcap`, `core/protocols`, `core/tls`, `core/ml` | Lead |
| `shared/contracts` | Lead |
| `datasets` + dataset generation | Member 2 |
| `core/rules` | Member 3 |
| `backend` + `reports` | Member 4 |
| `frontend` | Member 5 |
| `tests` + general `docs` | Member 6 |

### Collaboration and Conflict Prevention Rules

- **Respect Area Ownership**: Each member primarily edits owned folders. Do not edit another member's owned area without coordination.
- **Contract Authority**: Shared contracts are controlled by the lead.
- **Frontend Mocking**: Frontend should use mock JSON when backend is incomplete.
- **Backend Mocking**: Backend should use mocked core output when core is incomplete.
- **Structured Rule Consumption**: Rules should consume structured input rather than parse PCAP directly.
- **Branch & PR Lifecycle**:
  - `main` contains stable/demo-ready code only.
  - `develop` is the integration branch.
  - All feature branches merge into `develop` by Pull Request.
  - Keep PRs small and focused.
  - Pull latest `develop` before starting work.
  - Resolve conflicts on the feature branch before PR merge.

Before opening a Pull Request:

1. Pull the latest `develop` changes.
2. Run `python -m pytest`.
3. Run `npm run build` inside `frontend/` if frontend files changed.
4. Explain what changed, how it was tested, and any known limitations.
5. Do not commit real PCAPs, secrets, generated reports, virtual environments, dependencies, or trained model binaries.
6. Review `docs/PROJECT_CONTEXT.md` and update it if project state changed.

## Beginner Git Workflow

Each member works only on their assigned branch.

### Daily work

**macOS/Linux:**

```bash
./scripts/checkpoint.sh "what I worked on"
```

**Windows:**

```powershell
.\scripts\checkpoint.ps1 "what I worked on"
```

This command automatically:
- stages changes
- commits changes
- pushes to the member branch
- updates the member's Draft PR

### Rules

Members should NOT:
- push directly to `develop`
- push directly to `main`
- merge their own unfinished work

### When work is stable

When work is stable:
- tell the lead
- mark PR Ready for Review
- review
- merge into `develop`

## Project Context Maintenance

- `docs/PROJECT_CONTEXT.md` is the canonical AI/team context file.
- Every meaningful implementation PR must review it.
- Update it whenever implementation status, architecture, contracts, dependencies, ownership, milestones, limitations, or repository structure materially change.
- Never mark a feature implemented unless working code and relevant verification exist.
- Context changes should normally be committed with the related implementation.

## Conventional commits

Use a short, descriptive prefix:

```text
feat: add SMTP session schema
fix: handle missing tshark executable
docs: clarify Windows setup
test: cover health endpoint
refactor: simplify certificate metadata mapping
chore: update development dependencies
```


