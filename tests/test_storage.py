from datetime import datetime, timezone

from storage.database import count_events, insert_event
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

