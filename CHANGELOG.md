# Changelog

Changes are grouped by source release. Alpha tags are explicit; package metadata
currently remains `0.1.0` and registry publishing is disabled.

## Unreleased

- Community source release and public repository preparation.

## 0.1.0-alpha.1 — prepared October 31, 2026

This entry describes the first source alpha candidate; it is not a claim that a
GitHub release or package registry publication has occurred.

### Added

- Private agent memory, versioned shared proposals and owner approval/rejection.
- Authentication, credential expiry/revocation, agent revocation and logical quotas.
- Durable request IDs and atomic data/audit/receipt persistence.
- Local HTTP server, Python SDK and agent-only MCP bridge.
- Turso embedded and opt-in SQLCipher Community storage profiles.
- Independent backup keys, restore under new DB keys and credential invalidation.
- Verified offline migration, v3 streaming snapshots and operational backup helpers.
- Regression, malicious-input, retry, software-failure and recovery test tooling.
- Quick starts, architecture/limits guides, contribution policies and release checks.

### Known limits

- Developer alpha; no independent assessment or physical durability certification.
- Serialized operations, one shared workspace per database and local service scope.
- No exposed vector/FTS feature, native mobile binding, replication, SSO or hosted Pro.
- Sensitive production use requires the qualification described in [security](SECURITY.md).
