# HTTP API

The server binds to IPv4 loopback. All application endpoints require exactly one
`Authorization: Bearer SECRET` header; `/health` is generic public liveness.
Use the bound Host authority. Browser Origins, query strings and caller-supplied
roles are rejected. Cookies do not authenticate requests. POST bodies are
strict JSON objects.

## Endpoints

| Method / path | Principal | Body |
|---|---|---|
| GET `/health` | Public | None |
| GET `/v1/me` | Owner or agent | None |
| POST `/v1/memory/remember` | Agent | `key`, `value` |
| POST `/v1/memory/recall` | Agent | `key` |
| POST `/v1/shared/read` | Owner or agent | `key` |
| POST `/v1/proposals/create` | Agent | `key`, `value` |
| POST `/v1/operations/status` | Owner or agent | `id` |
| POST `/v1/admin/agents` | Owner | `ttl_seconds` |
| POST `/v1/admin/credentials/issue` | Owner | `agent_id`, `ttl_seconds` |
| POST `/v1/admin/credentials/revoke` | Owner | `id` |
| POST `/v1/admin/agents/revoke` | Owner | `id` |
| POST `/v1/admin/proposals/inspect` | Owner | `id` |
| POST `/v1/admin/proposals/approve` | Owner | `id` |
| POST `/v1/admin/proposals/reject` | Owner | `id` |
| POST `/v1/admin/audit` | Owner | `after`, `limit` |

The remember/propose/approve/reject/revoke endpoints also accept optional
`operation_id`. Reuse the same ID and input after an uncertain response.
Status lookup is scoped to the authenticated principal. A missing receipt does
not exclude a request still committing.

Provisioning returns `agent_id`, `credential_id` and the secret. The credential
ID is an identifier, not a bearer secret. Store the secret securely on delivery;
it cannot be retrieved later. The API does not provision owner authority, accept
SQL, open caller-selected database paths or expose backup files.

## Results and errors

Successful writes return `{"ok":true}`; proposal creation returns `{"id":...}`.
Memory/shared reads return `{"value":...}`. Proposal inspection returns
`{"proposal":...}`. Operation lookup returns `{"operation":...}`, where a
committed receipt includes action, result, ID and creation time. Audit returns
`{"events":[...]}`. See the [SDK](../sdk/python/dolphi/__init__.py) for exact calls.

Errors use safe codes instead of SQL, file paths, keys or engine messages:

| HTTP status | Meaning |
|---|---|
| 400 | Invalid fields or input |
| 401 | Missing, invalid, expired or revoked credential |
| 403 | Role/authority denied |
| 409 | Stale proposal or conflicting operation-ID reuse |
| 413 | Body limit |
| 429 | Quota or ingress limit |
| 500 | Internal failure |

Near a transport failure/timeout, preserve the operation ID and inspect/reconcile
the result. Do not assume no response means rollback.

## Transport bounds

Bodies are at most 96 KiB. Connections have 32-header / 128 KiB header bounds,
a five-second incomplete-header deadline, ten-second application timeout and
fifteen-second connection lifetime. Keep-alive is disabled. The server allows
128 accepted connections and 32 concurrent application calls; core operations
remain serialized. A per-process 1,200/minute ingress budget counts denied and
malformed attempts that reach the application. Audit pages contain 1–1,000 events.

These controls do not establish a public TLS deployment or distributed DoS
protection. See [security](../SECURITY.md) and [limits](LIMITS.md).
