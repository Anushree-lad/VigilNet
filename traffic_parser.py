"""
traffic_parser.py
-----------------
Reads a PCAP/PCAPNG file and converts network packets into
normalized PacketRecord objects.

Supports:
- IPv4
- IPv6
- TCP
- UDP
- ICMP
- ICMPv6
"""

from dataclasses import dataclass
from typing import List, Optional

from scapy.all import rdpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6Unknown


@dataclass
class PacketRecord:
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    length: int
    tcp_flags: str


def parse_pcap(path: str) -> List[PacketRecord]:
    """
    Reads a PCAP/PCAPNG file and converts IPv4/IPv6
    network packets into normalized PacketRecord objects.
    """

    packets = rdpcap(path)
    records: List[PacketRecord] = []

    for pkt in packets:

        # -----------------------------
        # Detect IPv4 or IPv6
        # -----------------------------
        if IP in pkt:
            ip_layer = pkt[IP]

        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]

        else:
            # Ignore ARP, Ethernet-only, etc.
            continue

        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        src_port = None
        dst_port = None
        tcp_flags = ""
        protocol = "OTHER"

        # -----------------------------
        # TCP
        # -----------------------------
        if TCP in pkt:
            protocol = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_flags = str(pkt[TCP].flags)

        # -----------------------------
        # UDP
        # -----------------------------
        elif UDP in pkt:
            protocol = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        # -----------------------------
        # ICMP
        # -----------------------------
        elif ICMP in pkt:
            protocol = "ICMP"

        # -----------------------------
        # ICMPv6
        # -----------------------------
        elif ICMPv6Unknown in pkt:
            protocol = "ICMPv6"

        # -----------------------------
        # Create normalized record
        # -----------------------------
        records.append(
            PacketRecord(
                timestamp=float(pkt.time),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                length=len(pkt),
                tcp_flags=tcp_flags,
            )
        )

    return records


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python traffic_parser.py <pcap_file>")
        sys.exit(1)

    records = parse_pcap(sys.argv[1])

    print(f"Parsed {len(records)} IP packets")

    for record in records[:10]:
        print(record)