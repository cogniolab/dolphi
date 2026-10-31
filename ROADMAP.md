# Roadmap

This is a direction, not a delivery schedule. Proposals, experiments and
implemented features are distinguished explicitly.

## Available in Community alpha

- Rust memory core with private agent namespaces and owner-reviewed shared data.
- Expiring/revocable credentials, logical quotas and attributable mutation audit.
- Durable operation IDs, scoped receipt lookup and same-request retries.
- Default embedded and opt-in SQLCipher Community storage profiles.
- Encrypted snapshots, validated restore and offline cross-profile migration.
- Bounded v3 streaming snapshots and operational backup/retention helpers.
- Loopback HTTP API, Python SDK, agent-only MCP and executable examples.
- Automated permission, HTTP, recovery, retry and software-storage-failure tests.

## Community launch

- Publish a clean source repository, accessible docs and source alpha release.
- Establish private vulnerability reporting, maintainer contact and issue triage.
- Run hosted CI on the published repository and publish its actual results.
- Collect installation, workflow and platform feedback from early users.

## Production qualification

- Qualify declared hardware/filesystem/cache profiles, including physical loss.
- Complete an independent review and independently verify remediation.
- Accept supported capacity, full-service recovery objectives and key-disaster
  recovery; configure external alert delivery for intended deployments.
- Validate actual model/tool attack scenarios and supported OS/architectures.

These are production-readiness gates, not a blocker on an honestly labeled alpha.

## Future design work

Semantic/vector retrieval, full-text search, native mobile bindings, additional
workspace models and distributed sync require separate design and qualification.
Upstream engine support alone does not make these implemented Dolphi features.

## Planned Pro

Explore managed hosting, organization administration, operations, observability
and support. No paid service or availability commitment is announced. Community
safety features remain open source; see [edition principles](docs/COMMUNITY_AND_PRO.md).
