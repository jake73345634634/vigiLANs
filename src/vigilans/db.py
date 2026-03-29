import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent.parent / "vigilans.db"

SCHEMA = """\
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS imports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tool_name   TEXT NOT NULL,
    device_name TEXT NOT NULL,
    device_type TEXT NOT NULL DEFAULT '',
    report_date TEXT NOT NULL,
    filename    TEXT NOT NULL,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS rules (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id   INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
    rule_num    INTEGER NOT NULL,
    name        TEXT NOT NULL DEFAULT '',
    vdom        TEXT NOT NULL DEFAULT '',
    src_intf    TEXT NOT NULL DEFAULT '',
    dst_intf    TEXT NOT NULL DEFAULT '',
    src_addr    TEXT NOT NULL DEFAULT '',
    dst_addr    TEXT NOT NULL DEFAULT '',
    service     TEXT NOT NULL DEFAULT '',
    src_addr_expanded TEXT NOT NULL DEFAULT '',
    dst_addr_expanded TEXT NOT NULL DEFAULT '',
    service_expanded  TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL DEFAULT 'deny',
    log         TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'enable',
    nat         TEXT NOT NULL DEFAULT '',
    comments    TEXT NOT NULL DEFAULT '',
    schedule    TEXT NOT NULL DEFAULT '',
    raw         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS rule_issues (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    UNIQUE(rule_id, title)
);

CREATE TABLE IF NOT EXISTS raw_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    import_id   INTEGER NOT NULL REFERENCES imports(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    UNIQUE(import_id, title)
);
"""


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db() -> None:
    conn = get_db()
    try:
        conn.executescript(SCHEMA)
        # Migrate: add expanded columns if missing
        cols = {r[1] for r in conn.execute("PRAGMA table_info(rules)").fetchall()}
        for col in ("src_addr_expanded", "dst_addr_expanded", "service_expanded"):
            if col not in cols:
                conn.execute(f"ALTER TABLE rules ADD COLUMN {col} TEXT NOT NULL DEFAULT ''")
        conn.commit()
    finally:
        conn.close()


def clear_db() -> None:
    conn = get_db()
    try:
        conn.execute("DELETE FROM rule_issues")
        conn.execute("DELETE FROM rules")
        conn.execute("DELETE FROM raw_findings")
        conn.execute("DELETE FROM imports")
        conn.commit()
    finally:
        conn.close()
