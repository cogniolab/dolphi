# Dolphi Community v0.1.0-alpha.2

**Give your agents memory, keep control of your data.**

This developer alpha addresses a SQLCipher worker-lifetime gap found during
follow-up validation of alpha.1. The final worker handle now drains accepted
work and joins native connection cleanup before returning. Failed or canceled
opening uses the same lifecycle guard. Explicit asynchronous worker shutdown
still joins outside the async runtime; the fallback final drop can block.

The regression fails on the previous implementation and passes with the fix.
Hosted checks include the standalone worker tests and storage qualification
across ten fresh SQLCipher processes. Exact commit, job results, recovery scope
and source hashes are recorded in the release's `VALIDATION.json`.

This release also puts the tagline directly below the Dolphi logo and adds
source-code navigation and a README-first overview link.

The Community capabilities remain persistent private agent memory,
owner-reviewed shared changes, authentication/revocation, quotas, durable
receipts, encrypted recovery, backend migration, Rust/HTTP/Python and agent MCP.

Start with the [quick start](../docs/QUICKSTART.md). Both storage profiles remain
alpha. APIs/formats may change. Physical-storage power-loss qualification,
independent assessment and sensitive-production qualification remain open.
See [limits](../docs/LIMITS.md) and [security](../SECURITY.md).

The [published prerelease](https://github.com/cogniolab/dolphi/releases/tag/v0.1.0-alpha.2)
includes source, checksums and `VALIDATION.json`. All seven
[hosted CI jobs](https://github.com/cogniolab/dolphi/actions/runs/41256331196)
passed for release commit `a6a3f4ca357e44a3b1d1ed01bdc59a94f479edcc`.
