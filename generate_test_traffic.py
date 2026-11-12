"""
generate_test_traffic.py
-------------------------
Creates a synthetic PCAP file with a mix of:
  - normal traffic (a couple of hosts doing regular browsing-like connections)
  - a port scan (one host hitting many ports on a target quickly)
  - a SYN flood (one host sending many unacknowledged SYNs)
  - reconnaissance (one host probing many different destination IPs)

This gives you real packets to run the full pipeline against without
needing an actual network capture. Swap this out for a real .pcap once
you have one (e.g. from a lab VM or a public malware-traffic sample).
"""

from scapy.all import wrpcap
from scapy.layers.inet import IP, TCP
import random
import time

packets = []
base_time = time.time()


def add_packet(pkt, t_offset):
    pkt.time = base_time + t_offset
    packets.append(pkt)


# --- 1. Normal traffic: two hosts talking to a server on a couple of ports ---
# Irregular timing (like real browsing/app traffic) so it does NOT look like beaconing.
t = 0.0
for i in range(20):
    t += random.uniform(0.1, 3.0)
    pkt = IP(src="10.0.0.5", dst="10.0.0.100") / TCP(sport=random.randint(1024, 65535), dport=443, flags="S")
    add_packet(pkt, t)

# --- 2. Port scan: 10.0.0.18 scans 40 ports on 10.0.0.50 within a few seconds ---
scan_ports = random.sample(range(1, 2000), 40)
for i, port in enumerate(scan_ports):
    pkt = IP(src="10.0.0.18", dst="10.0.0.50") / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
    add_packet(pkt, 30 + i * 0.05)

# --- 3. SYN flood: 10.0.0.25 sends 80 unacknowledged SYNs to one port ---
for i in range(80):
    pkt = IP(src="10.0.0.25", dst="10.0.0.100") / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
    add_packet(pkt, 40 + i * 0.02)

# --- 4. Reconnaissance: 10.0.0.31 probes 18 different hosts on port 22 ---
for i in range(18):
    dst = f"10.0.0.{60 + i}"
    pkt = IP(src="10.0.0.31", dst=dst) / TCP(sport=random.randint(1024, 65535), dport=22, flags="S")
    add_packet(pkt, 50 + i * 0.3)

wrpcap("sample_traffic.pcap", packets)
print(f"Wrote {len(packets)} packets to sample_traffic.pcap")
