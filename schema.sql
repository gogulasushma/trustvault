CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('admin', 'owner', 'viewer')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id),
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    category TEXT,
    size_bytes INTEGER NOT NULL,
    uploaded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    document_id INTEGER NOT NULL REFERENCES documents(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    level TEXT NOT NULL CHECK (level IN ('read', 'edit')),
    granted_by INTEGER NOT NULL REFERENCES users(id),
    granted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (document_id, user_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    user_id INTEGER,
    action TEXT NOT NULL,
    document_id INTEGER,
    allowed INTEGER NOT NULL,
    details TEXT
);