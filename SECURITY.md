# Security policy

Dolphi Community is a developer alpha. We welcome private reports and publish
the limits of the current security model. No independent security audit,
production durability qualification or immunity to agent/cyberattacks is claimed.

## Reporting a vulnerability

Report vulnerabilities privately to [dev@cogniolab.com](mailto:dev@cogniolab.com).
This is the maintainer-confirmed monitored contact for Dolphi. Do not put exploit
details, keys, tokens or private databases in public issues.

You can also use [GitHub's private vulnerability reporting form](https://github.com/cogniolab/dolphi/security/advisories/new).
Private reporting is enabled for this public repository. The email above remains
available. See the [publication checklist](docs/RELEASING.md).

Include the affected version/profile, platform, prerequisites, reproduction with
synthetic data, expected/actual behavior and impact. Never send your real keys,
bearer tokens or customer data. After launch we aim to acknowledge reports within
five business days and provide an initial assessment or update within ten;
these are response goals, not a guaranteed support SLA.

## Supported versions

The latest Community alpha is the maintained evaluation branch. There is no LTS
or production-support promise. Fixes may require an upgrade; verify migrations
and backup compatibility before replacing an existing installation.

## Trust boundaries

The host application, operating system, process identity, database directory and
key management are trusted. `Owner` is administrative authority. Keep it and
owner credentials out of model tools. Bootstrap/direct embedded handles are
trusted host capabilities; use credential-backed access for external agents.

Dolphi checks credential identity, expiry and revocation, separates private
memory, requires owner review for shared updates, applies logical quotas and
records supported mutations with their durable receipts atomically. API field
privacy and authorization do not isolate hostile code running as the same OS
user. Raw-file/key access bypasses logical controls.

The HTTP service binds to loopback. Its request, ingress, connection and timeout
bounds are local defenses. Remote TLS/proxy/tenant designs are not provided.
The Python client refuses redirects/ambient proxies; MCP exposes only agent
tools. A missing receipt after a timeout does not prove rollback: preserve the
operation ID and reconcile the same request.

## Encryption and recovery

The default Turso profile uses upstream experimental encryption. The SQLCipher
Community profile uses pinned native sources and OpenSSL packaging with integrity
and signature checks. Both Dolphi profiles remain alpha. `Owner::open` is a
plaintext development API; use encrypted opening for persistent sensitive state.

Keep database and backup keys separate and recoverable. Losing a key can lose
data permanently. Restores invalidate imported credentials and require trusted
reissuance. Offline export requires all source writers stopped or cooperatively
excluded. Physical power-loss qualification and independent assessment remain
future production gates, not prerequisites for publishing this alpha source.

## Known boundaries

- Stored text remains untrusted. The database does not detect prompt injection
  or prevent a model exfiltrating data it is legitimately allowed to read.
- Host/root or same-account process compromise can expose files, keys and data.
- Owner authority is not attributed to distinct named people. Revoking an owner
  token does not automatically revoke capabilities or credentials it delegated.
- Audit history is append-only through the API, not through raw file/SQL access.
  Denied requests, shared reads and owner inspections are not all audited.
- Quotas account for logical records/bytes, not physical disk, CPU or distributed
  denial of service. Operators must bound resources and monitor capacity.
- No SSO, KMS, online rekey, distributed replication or public TLS deployment is
  supplied. Native/OS support must be verified for each declared platform.
- Backup helpers support scheduling and retention, but their safety depends on
  actual writer coordination, SSH trust, key custody and operational alerting.

See [limits](docs/LIMITS.md), [testing](docs/TESTING.md),
[architecture](docs/ARCHITECTURE.md) and [recovery](docs/BACKUP_AND_RESTORE.md).
Basic safety controls remain Community features.
