import os
import sqlite3
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

_default_db = BASE_DIR / 'data' / 'keygate.db'
DB_PATH = Path(os.environ.get('DB_PATH') or _default_db)
if not DB_PATH.is_absolute():
    DB_PATH = (BASE_DIR / DB_PATH).resolve()

SCHEMA = """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS resellers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pass_hash TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    balance_cents INTEGER NOT NULL DEFAULT 0 CHECK (balance_cents >= 0),
    active INTEGER NOT NULL DEFAULT 1,
    allow_single INTEGER NOT NULL DEFAULT 1,
    allow_unlimited INTEGER NOT NULL DEFAULT 1,
    allow_lifetime INTEGER NOT NULL DEFAULT 1,
    allowed_durations TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_display TEXT NOT NULL UNIQUE,
    key_norm TEXT NOT NULL UNIQUE,
    duration_minutes INTEGER,
    price_cents INTEGER NOT NULL DEFAULT 0,
    device_mode TEXT NOT NULL CHECK (device_mode IN ('single', 'unlimited')),
    hwid TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    created_by_role TEXT NOT NULL CHECK (created_by_role IN ('admin', 'reseller')),
    created_by_id INTEGER NOT NULL,
    activated_at INTEGER,
    expires_at INTEGER,
    last_verified_at INTEGER,
    verify_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_keys_creator ON keys (created_by_role, created_by_id);
CREATE INDEX IF NOT EXISTS idx_keys_status ON keys (status);
CREATE INDEX IF NOT EXISTS idx_keys_hwid ON keys (hwid);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    role TEXT NOT NULL CHECK (role IN ('admin', 'reseller')),
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS access_sessions (
    token_hash TEXT PRIMARY KEY,
    key_id INTEGER NOT NULL,
    hwid TEXT,
    ip TEXT,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_access_key ON access_sessions (key_id);

CREATE TABLE IF NOT EXISTS verify_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_id INTEGER,
    key_display TEXT NOT NULL DEFAULT '',
    ip TEXT NOT NULL DEFAULT '',
    hwid TEXT NOT NULL DEFAULT '',
    result TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'portal',
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_verifylog_created ON verify_log (created_at);

CREATE TABLE IF NOT EXISTS bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL CHECK (kind IN ('ip', 'hwid')),
    value TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    UNIQUE (kind, value)
);

CREATE TABLE IF NOT EXISTS plans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL DEFAULT '',
    duration_minutes INTEGER,
    price_cents INTEGER NOT NULL CHECK (price_cents >= 0),
    device_mode TEXT NOT NULL DEFAULT 'unlimited' CHECK (device_mode IN ('single', 'unlimited')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_plans_active ON plans (active);
"""

RESELLER_COLUMNS = (
    ('display_name', "TEXT NOT NULL DEFAULT ''"),
    ('allow_single', 'INTEGER NOT NULL DEFAULT 1'),
    ('allow_unlimited', 'INTEGER NOT NULL DEFAULT 1'),
    ('allow_lifetime', 'INTEGER NOT NULL DEFAULT 1'),
    ('allowed_durations', "TEXT NOT NULL DEFAULT ''"),
)

KEY_COLUMNS = (('price_cents', 'INTEGER NOT NULL DEFAULT 0'),)


def connect():
    conn = sqlite3.connect(str(DB_PATH), timeout=5.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA busy_timeout = 5000')
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = connect()
    try:
        conn.execute('PRAGMA journal_mode = WAL')
        conn.executescript(SCHEMA)
        _migrate(conn)
        _seed_plans(conn)
    finally:
        conn.close()


def _seed_plans(conn):
    seeded = conn.execute(
        "SELECT 1 FROM settings WHERE key = 'plans_seeded'"
    ).fetchone()
    if seeded:
        return
    count = conn.execute('SELECT COUNT(*) AS c FROM plans').fetchone()['c']
    if not count:
        conn.execute(
            'INSERT INTO plans (label, duration_minutes, price_cents, device_mode, active, created_at) '
            "VALUES (?, ?, ?, 'unlimited', 1, ?)",
            ('1 day', 1440, 100, int(time.time() * 1000)),
        )
    conn.execute(
        "INSERT INTO settings (key, value) VALUES ('plans_seeded', '1') "
        'ON CONFLICT(key) DO UPDATE SET value = excluded.value'
    )


def _migrate(conn):
    existing = {
        row['name'] for row in conn.execute('PRAGMA table_info(resellers)').fetchall()
    }
    for name, definition in RESELLER_COLUMNS:
        if name not in existing:
            conn.execute('ALTER TABLE resellers ADD COLUMN {} {}'.format(name, definition))
    conn.execute(
        "UPDATE resellers SET display_name = username WHERE TRIM(display_name) = ''"
    )
    key_columns = {
        row['name'] for row in conn.execute('PRAGMA table_info(keys)').fetchall()
    }
    for name, definition in KEY_COLUMNS:
        if name not in key_columns:
            conn.execute('ALTER TABLE keys ADD COLUMN {} {}'.format(name, definition))
    if not get_setting(conn, 'keys_priced'):
        conn.execute(
            "UPDATE keys SET price_cents = 100 "
            "WHERE created_by_role = 'reseller' AND price_cents = 0"
        )
        set_setting(conn, 'keys_priced', '1')


def get_setting(conn, key, default=None):
    row = conn.execute('SELECT value FROM settings WHERE key = ?', (key,)).fetchone()
    return row['value'] if row else default


def set_setting(conn, key, value):
    conn.execute(
        'INSERT INTO settings (key, value) VALUES (?, ?) '
        'ON CONFLICT(key) DO UPDATE SET value = excluded.value',
        (key, value),
    )
