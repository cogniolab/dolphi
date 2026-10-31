# Limits and compatibility

Dolphi Community is a developer alpha. These boundaries describe implemented
behavior; upstream engine capabilities are not automatically Dolphi features.

| Area | Current behavior |
|---|---|
| Deployment | Embedded library or IPv4-loopback HTTP service |
| Workspaces | One shared workspace per DB; private namespaces per agent |
| Concurrency | Operations serialize within a store |
| Lookup key | 1–256 UTF-8 bytes |
| Memory value | 1–65,536 UTF-8 bytes |
| Default agents | 1,000 |
| Default private memory | 1,000 records / 4 MiB logical key+value bytes per agent |
| Default retained proposals | 1,000 per agent |
| Default audit events | 1,000,000, with emergency-revocation reserve |
| Default credentials | 10,000 |
| Agent operation budget | 6,000 successful operations/minute by default |
| Credential lifetime | One second to 30 days |
| Operation ID | 1–128 ASCII letters, digits, underscores or hyphens |
| HTTP body | 96 KiB; strict JSON fields |
| Audit page | At most 1,000 events |
| Materialized SQLCipher query | 64 MiB |
| Legacy v1/v2 snapshot | 64 MiB logical/accounting bound |
| v3 snapshot | At most 4 GiB encrypted bytes; 1 MiB plaintext frames |

Quotas are logical accounting, not bounds on disk allocation, WAL, CPU or
untrusted request load. Aggregate databases may exceed legacy backup capacity.
Use v3 streaming backup when appropriate; the full 4 GiB limit has not been
qualified at every size. Disk for working copies, WAL, staging and restore is
additional to encrypted snapshot size.

Local testing has covered Linux ARM64 and a roughly 132 MB logical-data streaming
fixture. This is not an RPO/RTO guarantee, capacity benchmark comparison or
qualification of every hardware profile. Other OS/architectures need their own
native build and security/recovery verification. No native Swift/Kotlin binding
is included. The current optional provider packaging targets Linux/GNU tools.

Dolphi does not currently expose semantic/vector search, full-text search,
multiple named shared workspaces, distributed replication, SSO, KMS, online rekey,
browser approval UI or hosted Pro. The default Turso encryption API is upstream
experimental. Neither Dolphi profile is independently audited here.

The HTTP ingress budget and socket limits are per-process controls. They are not
distributed DDoS protection and can constrain legitimate administration during
abuse. Keep a trusted local incident-response path. Credential revocation is
checked per operation; an already-running operation may finish before revocation.

See [security](../SECURITY.md), [architecture](ARCHITECTURE.md),
[HTTP bounds](HTTP_API.md) and [backup behavior](BACKUP_AND_RESTORE.md).
