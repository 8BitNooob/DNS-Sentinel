"""Adapter for Zeek dns.log files when supplied on Windows."""

import csv
from datetime import datetime, timezone
from pathlib import Path

from storage.models import DnsEvent


def read_zeek_events(path: str | Path):
    with Path(path).open(encoding="utf-8") as file:
        headers = None
        for line in file:
            if line.startswith("#fields"):
                headers = line.rstrip().split("\t")[1:]
                continue
            if not line.startswith("#") and headers:
                row = dict(zip(headers, line.rstrip().split("\t")))
                if row.get("query") in {None, "-"}:
                    continue
                timestamp = datetime.fromtimestamp(float(row["ts"]), tz=timezone.utc)
                yield DnsEvent(
                    event_id=f"zeek-{row['ts']}-{row.get('uid', row['query'])}",
                    observed_at=timestamp, source_ip=row["id.orig_h"], source_port=0,
                    destination_ip=row["id.resp_h"], destination_port=int(row.get("id.resp_p", 53)),
                    transport="udp", transaction_id=0, qname=row["query"].rstrip(".").lower(),
                    qtype=row.get("qtype", "unknown"), is_response=True,
                    response_code={"NXDOMAIN": 3}.get(row.get("rcode_name"), 0),
                )
