# SecureMailScope Agent Rules

1. Read docs/PROJECT_CONTEXT.md before making changes.
2. Respect CODEOWNERS and team ownership boundaries.
3. Work only on the currently checked-out member branch.
4. Never push feature work directly to main or develop.
5. Do not silently change shared/contracts.
6. Work only on the requested task or milestone.
7. Run relevant tests before finishing.
8. Update docs/PROJECT_CONTEXT.md if the real project state changes.
9. Use the current member branch + Draft PR as the live record of in-progress work.
10. Do not merge PRs automatically.
11. Do not force push.
12. Do not rewrite Git history.
13. Do not commit secrets, PCAP datasets, trained model binaries, or generated reports unless explicitly approved.
14. Never claim unimplemented functionality is complete.

PROJECT STATE
= docs/PROJECT_CONTEXT.md

IN-PROGRESS WORK
= current member branch + Draft PR

CONFIRMED INTEGRATION
= develop

STABLE RELEASE
= main

Before finishing:
- run tests
- inspect git status
- update PROJECT_CONTEXT.md if needed
- report what changed
