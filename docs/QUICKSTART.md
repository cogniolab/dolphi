# Quick start

This guide uses the opt-in SQLCipher Community profile. Start from a source
checkout with current stable Rust, a C compiler, Make and Perl. The SDK requires
Python 3.10+; native verification scripts require Python 3.11+ and GnuPG.
See [development](DEVELOPMENT.md) for details.

The public source destination is `cogniolab/dolphi`:

```sh
git clone https://github.com/cogniolab/dolphi.git
cd dolphi
```

## Try the temporary example

```sh
cargo run --locked --no-default-features --features sqlcipher-backend --example community
```

It tests authenticated memory, owner approval, revocation and new-key recovery.
Its database and generated keys are temporary.

## Initialize a persistent database

Use a fresh private directory. Existing initialization destinations are refused.

```sh
umask 077
mkdir -p data/local
chmod 700 data/local
cargo build --locked --no-default-features --features sqlcipher-backend --bin dolphi-server
target/debug/dolphi-server init data/local/community.db data/local/database.key data/local/owner.token
target/debug/dolphi-server serve data/local/community.db data/local/database.key 8787
```

Leave this terminal running. The service binds to `127.0.0.1:8787` and prints its
address without credentials. The key is 32 raw bytes. Losing it loses access to
the encrypted database. Keep the owner token out of agent prompts, source
control and shell arguments.

## Run two workers

In another terminal at the repository root:

```sh
export PYTHONPATH="$PWD/sdk/python"
export DOLPHI_URL=http://127.0.0.1:8787
export DOLPHI_OWNER_TOKEN_FILE="$PWD/data/local/owner.token"
python3 sdk/python/examples/two_agents.py
```

Expected output:

```text
PASS: two authenticated workers, isolated memory, owner approval and shared summary
```

The inventory worker saves a private note and proposes a stock update. The
summary worker cannot see the note. A separate owner client approves the update.
This deterministic demo makes no model/provider calls. Your real application
must keep owner authority in trusted code or a review UI.

## Continue

- [Python and MCP](PYTHON_AND_MCP.md): provision credentials and connect tools.
- [HTTP API](HTTP_API.md): build a client in another language.
- [Backup and restore](BACKUP_AND_RESTORE.md): save an encrypted snapshot.
- [Limits](LIMITS.md): understand the alpha's boundaries.

Stop the service with Ctrl-C before offline backup, token administration or
migration. Data stays in `data/local`. Keep DB/WAL files, keys and credentials
private; do not commit them.
