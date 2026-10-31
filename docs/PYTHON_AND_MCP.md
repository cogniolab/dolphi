# Python and MCP

Start the encrypted service using the [quick start](QUICKSTART.md). The Python
SDK supports Python 3.10+ and has no third-party runtime dependencies.

From a checkout, set `PYTHONPATH` to `sdk/python`. Alternatively install the local
package in your virtual environment with `python -m pip install ./sdk/python`.
This does not imply a PyPI package has been published.

## Provision an agent from trusted code

This script runs with owner authority. Do not expose it as a model tool.

```python
import os
from pathlib import Path
from dolphi import Client

owner = Client("http://127.0.0.1:8787", Path("data/local/owner.token").read_text().strip())
registration = owner.create_agent(ttl_seconds=3600)
descriptor = os.open("data/local/agent.token", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(descriptor, "w") as token_file:
    token_file.write(registration["secret"])

agent = Client("http://127.0.0.1:8787", registration["secret"])
agent.remember("task", "Count inventory", operation_id="inventory-task-1")
assert agent.recall("task") == "Count inventory"
proposal_id = agent.propose("stock", "12 units", operation_id="inventory-proposal-1")
# Present this proposal for review in your trusted application before approving.
owner.approve(proposal_id, operation_id="inventory-review-1")
assert agent.read_shared("stock")["value"] == "12 units"
```

The snippet is a deterministic programming example; its comment is not a human
approval UI. In an actual workflow, wait for the review decision. Protect the
credential file and never print its contents. Re-running provisioning creates a
new agent; the example refuses to overwrite its existing token file.

For timeout recovery, call `agent.operation_status("inventory-task-1")` and
reconcile the same request with the same ID. The SDK does not retry mutations
automatically. It ignores ambient proxies, refuses redirects and redacts
credentials from its representation/errors. HTTPS uses default certificate checks.

## MCP bridge

Use an agent credential, never an owner credential. A representative client
configuration is below; adapt the outer configuration shape to your MCP host:

```json
{
  "mcpServers": {
    "dolphi": {
      "command": "python3",
      "args": ["-m", "dolphi.mcp"],
      "env": {
        "PYTHONPATH": "/absolute/checkout/sdk/python",
        "DOLPHI_URL": "http://127.0.0.1:8787",
        "DOLPHI_TOKEN_FILE": "/absolute/private/agent.token"
      }
    }
  }
}
```

Configure exactly one of `DOLPHI_TOKEN_FILE` and legacy `DOLPHI_TOKEN`.
Private files are preferred. Unix token files must deny group/other access;
symlinks, FIFOs and ambiguous credential sources are rejected. File paths in
the configuration are examples, not literal credentials.

The bridge implements protocol `2025-06-18`, JSON-RPC stdio initialization,
ping, tool discovery and calls. It exposes `memory_remember`, `memory_recall`,
`shared_read`, `proposal_create` and `operation_status`. Discovery/calls
reauthenticate through HTTP, so revocation is not hidden by a cached role.
Approval, raw SQL, file access and administrative provisioning are not tools.

Returned text is untrusted data. Your agent runtime controls tool access and
output handling; memory storage alone does not prevent prompt injection.
