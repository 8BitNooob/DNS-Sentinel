"""SQLite initialization and basic DNS event persistence."""

import sqlite3
import uuid
from pathlib import Path

from storage.models import DnsEvent
from storage.day5 import DAY5_SCHEMA


CREATE_DNS_EVENTS = """
CREATE TABLE IF NOT EXISTS dns_events (
    event_id TEXT PRIMARY KEY,
    observed_at TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    source_port INTEGER NOT NULL,
    destination_ip TEXT NOT NULL,
    destination_port INTEGER NOT NULL,
    transport TEXT NOT NULL,
    transaction_id INTEGER NOT NULL,
    qname TEXT NOT NULL,
    qtype TEXT NOT NULL,
    is_response INTEGER NOT NULL,
    response_code INTEGER,
    answers_json TEXT NOT NULL,
    ttl INTEGER,
    correlation_status TEXT NOT NULL
)
"""


def initialize_database(path: str | Path) -> None:
    """Create the database and canonical DNS event table if needed."""
    database_path = Path(path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(CREATE_DNS_EVENTS)
        connection.executescript(DAY5_SCHEMA)


def insert_event(path: str | Path, event: DnsEvent) -> None:
    """Persist one canonical DNS event."""
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO dns_events (
                event_id, observed_at, source_ip, source_port,
                destination_ip, destination_port, transport,
                transaction_id, qname, qtype, is_response,
                response_code, answers_json, ttl, correlation_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.observed_at.isoformat(),
                event.source_ip,
                event.source_port,
                event.destination_ip,
                event.destination_port,
                event.transport,
                event.transaction_id,
                event.qname,
                event.qtype,
                int(event.is_response),
                event.response_code,
                event.answers_json,
                event.ttl,
                event.correlation_status,
            ),
        )


def update_query_from_response(path: str | Path, response: DnsEvent) -> None:
    """Finalize the persisted query row when its response is observed."""
    if not response.is_response:
        return
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            UPDATE dns_events
            SET correlation_status = ?, response_code = ?, answers_json = ?, ttl = ?
            WHERE event_id = (
                SELECT event_id FROM dns_events
                WHERE is_response = 0 AND correlation_status = 'pending'
                  AND source_ip = ? AND source_port = ?
                  AND destination_ip = ? AND destination_port = ?
                  AND transport = ? AND transaction_id = ?
                  AND qname = ? AND qtype = ?
                ORDER BY observed_at DESC LIMIT 1
            )
            """,
            (
                response.correlation_status,
                response.response_code,
                response.answers_json,
                response.ttl,
                response.destination_ip,
                response.destination_port,
                response.source_ip,
                response.source_port,
                response.transport,
                response.transaction_id,
                response.qname,
                response.qtype,
            ),
        )


def insert_alert(path: str | Path, client_ip: str, domain: str, alert, score: int = 0) -> None:
    """Persist a deduplicated detector alert."""
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO alerts
            (alert_id, observed_at, client_ip, domain, rule, evidence, score)
            VALUES (?, datetime('now'), ?, ?, ?, ?, ?)
            """,
            (
                str(uuid.uuid5(uuid.NAMESPACE_URL, f"{client_ip}|{domain}|{alert.rule}|{alert.evidence}")),
                client_ip,
                domain,
                alert.rule,
                alert.evidence,
                score,
            ),
        )


def count_events(path: str | Path) -> int:
    """Return the number of persisted DNS events."""
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        return connection.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0]
