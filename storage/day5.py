"""SQLite persistence for Day 5 baselines, alerts, incidents, and allowlists."""

import sqlite3
from pathlib import Path

DAY5_SCHEMA = """
CREATE TABLE IF NOT EXISTS client_baselines (
    client_ip TEXT PRIMARY KEY, sample_count INTEGER NOT NULL,
    query_rate_median REAL NOT NULL, unique_domain_median REAL NOT NULL,
    nxdomain_rate_median REAL NOT NULL, trusted INTEGER NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY, observed_at TEXT NOT NULL, client_ip TEXT NOT NULL,
    domain TEXT NOT NULL, rule TEXT NOT NULL, evidence TEXT NOT NULL,
    score INTEGER NOT NULL, suppressed INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alerts_client_domain ON alerts(client_ip, domain);
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY, first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
    client_ip TEXT NOT NULL, domain TEXT NOT NULL, rules_json TEXT NOT NULL,
    score INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS allowlist (
    entry_id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, value TEXT NOT NULL,
    detector TEXT, expires_at TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL
);
"""


def initialize_day5(path: str | Path) -> None:
    database_path = Path(path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.executescript(DAY5_SCHEMA)


def save_baseline(path: str | Path, baseline, updated_at: str) -> None:
    initialize_day5(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """INSERT OR REPLACE INTO client_baselines
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (baseline.client_ip, baseline.sample_count, baseline.query_rate_median,
             baseline.unique_domain_median, baseline.nxdomain_rate_median,
             int(baseline.trusted), updated_at),
        )


def count_day5_rows(path: str | Path, table: str) -> int:
    if table not in {"client_baselines", "alerts", "incidents", "allowlist", "settings"}:
        raise ValueError("Unsupported Day 5 table")
    initialize_day5(path)
    with sqlite3.connect(path) as connection:
        return connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
