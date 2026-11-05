import sqlite3
from datetime import datetime, timezone

from storage.database import count_events, insert_event, update_query_from_response
from storage.models import DnsEvent


def test_insert_and_read_dns_event(tmp_path):
    database_path = tmp_path / "events.sqlite3"
    event = DnsEvent(
        event_id="day1-sample",
        observed_at=datetime.now(timezone.utc),
        source_ip="192.168.42.66",
        source_port=53000,
        destination_ip="8.8.8.8",
        destination_port=53,
        transport="udp",
        transaction_id=42,
        qname="example.com.",
        qtype="A",
        is_response=False,
    )

    insert_event(database_path, event)

    assert count_events(database_path) == 1


def test_response_finalizes_persisted_query(tmp_path):
    database_path = tmp_path / "events.sqlite3"
    query = DnsEvent(
        event_id="query", observed_at=datetime.now(timezone.utc),
        source_ip="192.168.42.66", source_port=53000,
        destination_ip="8.8.8.8", destination_port=53, transport="udp",
        transaction_id=42, qname="missing.example", qtype="A", is_response=False,
        correlation_status="pending",
    )
    response = DnsEvent(
        event_id="response", observed_at=query.observed_at,
        source_ip="8.8.8.8", source_port=53,
        destination_ip="192.168.42.66", destination_port=53000, transport="udp",
        transaction_id=42, qname="missing.example", qtype="A", is_response=True,
        response_code=3, correlation_status="matched",
    )
    insert_event(database_path, query)
    insert_event(database_path, response)
    update_query_from_response(database_path, response)
    with sqlite3.connect(database_path) as connection:
        row = connection.execute(
            "SELECT correlation_status, response_code FROM dns_events WHERE event_id = 'query'"
        ).fetchone()
    assert row == ("matched", 3)
