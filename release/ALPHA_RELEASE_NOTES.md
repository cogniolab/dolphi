# Dolphi Community v0.1.0-alpha.1

**Give your agents memory, keep control of your data.**

This source alpha introduces persistent private agent memory, trusted-owner
shared proposals, authentication/revocation, logical quotas and durable retries.
It includes a Rust library, local HTTP server, Python SDK and agent-only MCP.

Recovery includes independent backup keys, verified new-key restore, credential
invalidation, cross-profile migration and bounded streaming snapshots. The
default engine is MIT Turso; SQLCipher Community is an opt-in build profile.
Basic safety controls and operational backup helpers are Community features.

Start with the [quick start](../docs/QUICKSTART.md). The release is source-first;
no hosted Pro service or registry package publication is announced.

This is a developer preview. APIs/formats may change. Physical-storage durability,
independent security assessment, production recovery objectives and additional
platforms remain unqualified. See [limits](../docs/LIMITS.md),
[security](../SECURITY.md) and [roadmap](../ROADMAP.md).

The release notes are prepared text until a public repository and prerelease
exist. Attach actual checksums and CI results at publication.
