# Architecture

Dolphi adds agent-memory and approval semantics above an embedded storage
engine. The Rust core owns authorization, schema, transactions, quotas, audit
events and durable receipts. HTTP adapts these capabilities for external clients;
the Python SDK and MCP bridge use that API.

## Private memory and shared state

Each agent has a fixed identity and private key/value namespace. A memory call
cannot select another identity with a caller-supplied agent ID: its bearer
credential determines identity.

All active agents in a database share one common workspace. Agents propose
updates against the current shared version. The trusted owner approves or
rejects them. Approval rejects stale versions. Use separate databases for
independently administered workspaces.

## Authority

`Owner` is a bootstrap/administrative capability. File access, provisioning and
embedded handle creation belong in trusted host code. Credential-backed handles
recheck expiry/revocation on every operation. MCP omits approval/admin tools.

This is logical authorization. A process with the raw database and keys can
bypass it. Use separate OS identities for untrusted native code. Memory remains
untrusted data even when it looks like instructions.

## Transactions and retries

Tracked mutations save state, audit events and operation receipts atomically.
An operation ID is scoped to its principal. Repeating the same ID/input returns
the original result; changed input conflicts. Preserve IDs across transport
errors. A missing receipt cannot rule out work still in flight. The SDK does
not automatically retry mutations. Operations currently serialize within a store.

## Storage profiles

| Profile | Build | Boundary |
|---|---|---|
| Default embedded | Default Cargo features | MIT Turso 0.8.3; upstream page encryption is experimental |
| SQLCipher Community | `--no-default-features --features sqlcipher-backend` | SQLCipher 4.20 / SQLite 3.54.1 with pinned OpenSSL 3.5.9 LTS sources |

Select exactly one profile. Both have application regression coverage; neither
is advertised as an independently audited Dolphi production deployment.
Encrypted files are not plaintext SQLite files. Use [migration](BACKUP_AND_RESTORE.md#changing-storage-profiles)
to change profiles, rather than opening the same files with a different engine.

The SQLCipher adapter and pinned native packaging live under
`experiments/sqlcipher`. No commercial engine or hosted account is required.
Their native notices, checksums and source/signature checks ship with the source.

The SQLCipher connection runs on a dedicated native worker. Explicit worker
shutdown joins it outside the async runtime. Dropping the final worker handle
also waits for accepted work and native connection cleanup; this final drop can
block its calling thread. Worker startup failure and canceled opening follow the
same cleanup path. Connections must finish closing before process-wide crypto
cleanup begins.

## Recovery

Logical snapshots contain ten application tables. Restore validates rows,
relationships and receipts, revokes imported credentials, checks integrity and
publishes to a new destination. Version 3 streams authenticated bounded frames;
legacy v1/v2 snapshots remain readable.

The operational backup helper coordinates stopped writers, sends ciphertext
through verified SSH, restores it on another host and runs service probes before
marking it verified. Operators manage keys, retention, limits and alert delivery.
See [backup and restore](BACKUP_AND_RESTORE.md).

## Prepublication rename compatibility

Dolphi was previously named MimiDB. Public package, command and environment names
now use Dolphi. Existing snapshot magic/AAD identifiers (`MIMIDB-BACKUP-*`) and
signed OpenSSL package suffixes remain unchanged so earlier encrypted backups
and native source checks remain valid. On-disk table schemas, agent identities,
authorization semantics and HTTP `/v1` endpoints are unchanged by the rename.
