# Testing and evidence

Dolphi tests authorization and recovery behavior using synthetic fixtures.
They are internal engineering evidence, not an independent assessment.

## Product regression

Locally retained runs before public release preparation passed 71 runtime tests
with the default embedded profile and 74 with SQLCipher Community, plus four
compile-fail capability checks and 14 Python/socket/SDK/MCP tests per profile.
New release checks also verify the public export, links and example setup.
Run [development commands](DEVELOPMENT.md) to reproduce results on your platform.
Hosted CI status is reported only after a real run on the public repository.

Coverage includes credential expiry/revocation, agent/owner isolation, stale
proposals, quotas, malicious SQL-like input, bounded HTTP/MCP input, redirect/
proxy refusal, committed receipts, lost-response reconciliation and restart.
Snapshot tests reject wrong keys, corruption, truncation, reordered/duplicated/
spliced frames and existing-destination overwrite.

## Storage and operations

Linux test tooling covers injected ENOSPC/EIO, partial writes, fsync failures,
interrupted checkpoint/export/restore, retry reconciliation and actual private
tmpfs space/inode exhaustion. The retained internal matrices include 139 legacy
storage-failure cases and 11 v3 artifact cases. An operational fixture adds 18
checks for coordination, interrupted controller recovery, key failures, transfer
integrity, retention, quotas and snapshot age.

A roughly 132 MB logical-data streaming fixture passed under a 512 MiB cgroup;
real off-host restore and a VM flush-prefix replay have separate internal
evidence. A power-loss witness has 12 process-rehearsal checks on each deployed
artifact, including a valid older-database negative control.

These observations do not establish all capacity, hardware or OS guarantees.
The public source package contains reproducible tools and a sanitized summary;
private host inventories, live records, access details and witness credentials
are deliberately excluded.

## Remaining qualification

Physical device/controller power-loss trials, independent security assessment,
full-service production RPO/RTO acceptance and actual model/tool attack evaluation
remain open. Community alpha publication is separate from that production
qualification. See [security](../SECURITY.md) and [roadmap](../ROADMAP.md).
