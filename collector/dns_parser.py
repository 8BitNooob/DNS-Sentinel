"""Convert captured Scapy packets into canonical DNS events."""

import json
import uuid
from datetime import datetime, timezone

from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet

from storage.models import DnsEvent


def _endpoint(packet: Packet) -> tuple[str, str, int, int, str] | None:
    if packet.haslayer(IP):
        network = packet[IP]
    elif packet.haslayer(IPv6):
        network = packet[IPv6]
    else:
        return None

    if packet.haslayer(UDP):
        transport = packet[UDP]
        protocol = "udp"
    elif packet.haslayer(TCP):
        transport = packet[TCP]
        protocol = "tcp"
    else:
        return None

    return network.src, network.dst, transport.sport, transport.dport, protocol


def _qtype_name(value: int) -> str:
    names = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }
    return names.get(value, str(value))


def _answer_records(dns: DNS) -> tuple[str, int | None]:
    records: list[dict[str, object]] = []
    ttl_values: list[int] = []
    answer = dns.an
    answer_count = dns.ancount or (1 if answer is not None else 0)
    for _ in range(answer_count):
        if answer is None:
            break
        record: dict[str, object] = {
            "name": answer.rrname.decode(errors="replace").rstrip("."),
            "type": _qtype_name(answer.type),
            "ttl": answer.ttl,
            "data": answer.rdata.decode(errors="replace")
            if isinstance(answer.rdata, bytes)
            else str(answer.rdata),
        }
        records.append(record)
        ttl_values.append(answer.ttl)
        answer = answer.payload if isinstance(answer.payload, DNSRR) else None
    return json.dumps(records, separators=(",", ":")), min(ttl_values) if ttl_values else None


def packet_to_event(packet: Packet) -> DnsEvent | None:
    """Return a canonical event for a DNS packet, or None for malformed input."""
    if not packet.haslayer(DNS):
        return None
    endpoint = _endpoint(packet)
    dns = packet[DNS]
    if endpoint is None or dns.qd is None:
        return None

    source_ip, destination_ip, source_port, destination_port, transport = endpoint
    qname = dns.qd.qname.decode(errors="replace").rstrip(".").lower()
    observed_at = datetime.fromtimestamp(float(packet.time), tz=timezone.utc)
    answers_json, ttl = _answer_records(dns) if dns.qr else ("[]", None)
    return DnsEvent(
        event_id=str(uuid.uuid4()),
        observed_at=observed_at,
        source_ip=source_ip,
        source_port=source_port,
        destination_ip=destination_ip,
        destination_port=destination_port,
        transport=transport,
        transaction_id=dns.id,
        qname=qname,
        qtype=_qtype_name(dns.qd.qtype),
        is_response=bool(dns.qr),
        response_code=dns.rcode if dns.qr else None,
        answers_json=answers_json,
        ttl=ttl,
    )
