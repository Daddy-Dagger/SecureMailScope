# Dataset guide

## Safety and provenance

Use only captures the team is authorized to inspect. Network captures may contain credentials, addresses, message content, cookies, and other personal data. Never collect or share traffic without permission.

For every intentionally shared fixture, document:

- how and when it was produced;
- whether all participants consented;
- its protocol scenario and expected observable behavior;
- sanitization applied;
- license or redistribution terms;
- a file hash for reproducibility.

## Local layout

The `datasets/` folders group normal, weak-TLS, certificate, STARTTLS, and mixed scenarios. Their contents are ignored by Git. Test fixtures should be minimal and synthetic or sanitized; adding a capture to version control requires an explicit ignore exception and Pull Request review.

`scripts/generate_test_data.py` is intentionally a placeholder. It does not fabricate captures or security results.

