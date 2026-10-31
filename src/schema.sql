CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS revoked_agents (agent_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS credentials (
    digest TEXT PRIMARY KEY, role TEXT NOT NULL, agent_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS request_windows (
    agent_id TEXT PRIMARY KEY, window INTEGER NOT NULL, requests INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS memories (
    agent_id TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
    PRIMARY KEY (agent_id, key)
);
CREATE TABLE IF NOT EXISTS shared (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proposals (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, key TEXT NOT NULL,
    value TEXT NOT NULL, base_version INTEGER NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected'))
);
CREATE TABLE IF NOT EXISTS audit (
    sequence INTEGER PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL,
    subject TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS operations (
    role TEXT NOT NULL CHECK(role IN ('owner','agent')),
    principal TEXT NOT NULL, operation_id TEXT NOT NULL,
    action TEXT NOT NULL, fingerprint TEXT NOT NULL, result TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(role, principal, operation_id)
);
