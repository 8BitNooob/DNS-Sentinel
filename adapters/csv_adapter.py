"""CSV DNS event adapter."""

import csv
import json
from datetime import datetime
from pathlib import Path

from storage.models import DnsEvent


def _bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "response"}


def read_csv_events(path: str | Path):
    with Path(path).open(newline="", encoding="utf-8") as file:
        for row in csv.DictReader(file):
            yield DnsEvent(
                event_id=row.get("event_id") or f"csv-{row['observed_at']}-{row['transaction_id']}",
                observed_at=datetime.fromisoformat(row["observed_at"]),
                source_ip=row["source_ip"], source_port=int(row["source_port"]),
                destination_ip=row["destination_ip"], destination_port=int(row["destination_port"]),
                transport=row.get("transport", "udp"), transaction_id=int(row["transaction_id"]),
                qname=row["qname"].rstrip(".").lower(), qtype=row["qtype"],
                is_response=_bool(row["is_response"]),
                response_code=int(row["response_code"]) if row.get("response_code") else None,
                answers_json=row.get("answers_json", "[]"), ttl=int(row["ttl"]) if row.get("ttl") else None,
            )
