from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP

from collector.dns_parser import packet_to_event


def test_packet_to_event_parses_query():
    packet = (
        IP(src="192.168.42.66", dst="8.8.8.8")
        / UDP(sport=53000, dport=53)
        / DNS(id=7, rd=1, qd=DNSQR(qname="Example.COM.", qtype="A"))
    )

    event = packet_to_event(packet)

    assert event is not None
    assert event.qname == "example.com"
    assert event.qtype == "A"
    assert not event.is_response
    assert event.response_code is None


def test_packet_to_event_parses_response_and_answer():
    packet = (
        IP(src="8.8.8.8", dst="192.168.42.66")
        / UDP(sport=53, dport=53000)
        / DNS(
            id=7,
            qr=1,
            an=DNSRR(rrname="example.com.", type="A", ttl=60, rdata="93.184.216.34"),
            qd=DNSQR(qname="example.com.", qtype="A"),
        )
    )

    event = packet_to_event(packet)

    assert event is not None
    assert event.is_response
    assert event.response_code == 0
    assert event.ttl == 60
    assert "93.184.216.34" in event.answers_json


def test_packet_to_event_ignores_non_dns_packets():
    assert packet_to_event(IP() / UDP()) is None


def test_packet_to_event_supports_tcp_dns():
    packet = (
        IP(src="192.168.42.66", dst="8.8.8.8")
        / TCP(sport=53000, dport=53)
        / DNS(id=8, rd=1, qd=DNSQR(qname="example.com.", qtype="AAAA"))
    )

    event = packet_to_event(packet)

    assert event is not None
    assert event.transport == "tcp"
    assert event.qtype == "AAAA"
