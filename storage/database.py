"""SQLite initialization and basic DNS event persistence."""

import sqlite3
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


def count_events(path: str | Path) -> int:
    """Return the number of persisted DNS events."""
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        return connection.execute("SELECT COUNT(*) FROM dns_events").fetchone()[0]
