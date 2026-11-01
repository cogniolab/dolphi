# Changelog

Changes are grouped by source release. Alpha tags are explicit; package metadata
currently remains `0.1.0` and registry publishing is disabled.

## Unreleased

Future work is tracked in the [roadmap](ROADMAP.md).

## 0.1.0-alpha.2 — prepared October 31, 2026

Addresses the worker-lifetime gap found while investigating native process crashes
and recovery failures in follow-up validation of alpha.1. Publication and exact
validation results are recorded with the release.

### Fixed

- Join SQLCipher worker teardown on final drop and failed/canceled opening,
  preventing native cleanup from continuing after its owning handle returns.
- Add worker-lifetime regression coverage and repeated process-exit qualification.

### Changed

- Position the tagline beneath the Dolphi logo and add source-code navigation.
- Publish a README-first link through the repository's About section.

## 0.1.0-alpha.1 — October 31, 2026

Published as a [Community developer prerelease](https://github.com/cogniolab/dolphi/releases/tag/v0.1.0-alpha.1).
Source archives, checksums and the validation report are available with the release.
Cargo/PyPI package publishing remains disabled.

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
