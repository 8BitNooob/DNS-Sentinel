"""PCAP DNS event adapter using the same packet parser as live capture."""

from pathlib import Path

from scapy.utils import PcapReader

from collector.dns_parser import packet_to_event


def read_pcap_events(path: str | Path):
    with PcapReader(str(path)) as reader:
        for packet in reader:
            event = packet_to_event(packet)
            if event is not None:
                yield event
