"""
DB Migration — adds all new columns from models.py v2
Safe to run multiple times (uses ALTER TABLE IF NOT EXISTS pattern via try/except).
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "tgcsb_cases.db")


def _add_column(cursor, table: str, column: str, col_type: str, default=None):
    try:
        stmt = f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"
        if default is not None:
            stmt += f" DEFAULT {default}"
        cursor.execute(stmt)
        print(f"  + {table}.{column}")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e).lower():
            pass   # already exists
        else:
            raise


def run():
    print(f"Migrating: {DB_PATH}")
    conn = sqlite3.connect(DB_PATH)
    c    = conn.cursor()

    # ── apks ──────────────────────────────────────────────────────────────
    _add_column(c, "apks", "total_loss_inr",  "REAL",    0.0)
    _add_column(c, "apks", "monitor_active",  "INTEGER", 0)
    _add_column(c, "apks", "last_monitored",  "TEXT")
    # Static-analysis intelligence (engine v2). JSON stored as TEXT in SQLite.
    _add_column(c, "apks", "malware_tags",    "TEXT")
    _add_column(c, "apks", "behaviors",       "TEXT")
    _add_column(c, "apks", "c2_channel",      "TEXT")
    _add_column(c, "apks", "c2_detail",       "TEXT")
    _add_column(c, "apks", "risk_breakdown",  "TEXT")
    _add_column(c, "apks", "cert_schemes",    "TEXT")

    # ── victims ───────────────────────────────────────────────────────────
    _add_column(c, "victims", "total_debited", "REAL",  0.0)
    _add_column(c, "victims", "debit_count",   "INTEGER", 0)
    _add_column(c, "victims", "state",         "TEXT")
    _add_column(c, "victims", "city",          "TEXT")
    _add_column(c, "victims", "latitude",      "REAL")
    _add_column(c, "victims", "longitude",     "REAL")

    # ── leads ─────────────────────────────────────────────────────────────
    _add_column(c, "leads", "assigned_to", "INTEGER")
    _add_column(c, "leads", "status",      "TEXT",   "'OPEN'")
    _add_column(c, "leads", "notes",       "TEXT")
    _add_column(c, "leads", "closed_at",   "TEXT")

    # ── new tables (create if not exists) ─────────────────────────────────
    c.executescript("""
    CREATE TABLE IF NOT EXISTS transactions (
        id             INTEGER PRIMARY KEY AUTOINCREMENT,
        apk_id         TEXT REFERENCES apks(id),
        victim_id      INTEGER REFERENCES victims(id),
        amount         REAL,
        currency       TEXT DEFAULT 'INR',
        txn_type       TEXT,
        bank_name      TEXT,
        account_last4  TEXT,
        upi_id         TEXT,
        recipient_name TEXT,
        txn_ref        TEXT,
        txn_date       TEXT,
        raw_sms        TEXT,
        created_at     TEXT
    );

    CREATE TABLE IF NOT EXISTS monitor_alerts (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        apk_id      TEXT REFERENCES apks(id),
        alert_type  TEXT,
        severity    TEXT,
        message     TEXT,
        detail      TEXT,
        seen        INTEGER DEFAULT 0,
        created_at  TEXT
    );

    CREATE TABLE IF NOT EXISTS officers (
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        name          TEXT NOT NULL,
        badge_number  TEXT UNIQUE,
        designation   TEXT,
        unit          TEXT,
        email         TEXT,
        phone         TEXT,
        username      TEXT UNIQUE NOT NULL,
        password_hash TEXT,
        role          TEXT DEFAULT 'ANALYST',
        is_active     INTEGER DEFAULT 1,
        created_at    TEXT,
        last_login    TEXT
    );

    CREATE TABLE IF NOT EXISTS lead_assignments (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        lead_id     INTEGER REFERENCES leads(id),
        officer_id  INTEGER REFERENCES officers(id),
        action      TEXT,
        old_status  TEXT,
        new_status  TEXT,
        note        TEXT,
        deadline    TEXT,
        created_at  TEXT
    );
    """)

    conn.commit()
    conn.close()
    print("Migration complete.")


if __name__ == "__main__":
    run()
