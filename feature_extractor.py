"""
feature_extractor.py
---------------------
Extracts network behavior features using time windows.

VigilNet v2:
Instead of analyzing the entire PCAP at once,
traffic is divided into small time windows.

Default:
- Window size = 10 seconds
- Step = 5 seconds
"""

from dataclasses import dataclass, field
from typing import Dict, List, Set

from traffic_parser import PacketRecord


@dataclass
class FlowFeatures:
    """Behavior of one source IP inside one time window."""

    src_ip: str

    # Time window
    window_start: float = 0.0
    window_end: float = 0.0

    # Traffic statistics
    total_packets: int = 0
    total_bytes: int = 0

    # Network behavior
    unique_destinations: Set[str] = field(default_factory=set)
    unique_dst_ports: Set[int] = field(default_factory=set)
    connection_count: int = 0

    # TCP behavior
    syn_count: int = 0

    # Protocol information
    protocols: Set[str] = field(default_factory=set)

    # Time information
    first_seen: float = 0.0
    last_seen: float = 0.0

    # Used for beaconing detection
    timestamps: List[float] = field(default_factory=list)

    @property
    def duration(self) -> float:
        """Duration of traffic inside this window."""
        return max(self.last_seen - self.first_seen, 0.0)

    def to_dict(self) -> dict:
        """Return a compact feature summary."""

        return {
            "src_ip": self.src_ip,
            "window_start": round(self.window_start, 2),
            "window_end": round(self.window_end, 2),
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "unique_destinations": len(self.unique_destinations),
            "unique_dst_ports": len(self.unique_dst_ports),
            "connection_count": self.connection_count,
            "duration_seconds": round(self.duration, 2),
            "syn_count": self.syn_count,
            "protocols": sorted(self.protocols),
        }


def extract_features(
    records: List[PacketRecord],
    window_size: float = 10.0,
    step: float = 5.0,
) -> Dict[str, List[FlowFeatures]]:
    """
    Divide packets into sliding time windows and extract
    features for each source IP inside each window.

    Parameters:
        records:
            Parsed network packets.

        window_size:
            Size of each detection window in seconds.

        step:
            How far the window moves forward each time.

    Returns:
        Dictionary:

        {
            "source_ip": [
                FlowFeatures(...),
                FlowFeatures(...),
            ]
        }
    """

    if not records:
        return {}

    # Sort packets by timestamp
    records = sorted(records, key=lambda packet: packet.timestamp)

    start_time = records[0].timestamp
    end_time = records[-1].timestamp

    results: Dict[str, List[FlowFeatures]] = {}

    window_start = start_time

    while window_start <= end_time:

        window_end = window_start + window_size

        # Packets belonging to this window
        window_packets = [
            packet
            for packet in records
            if window_start <= packet.timestamp < window_end
        ]

        if window_packets:

            # Group packets by source IP
            grouped: Dict[str, List[PacketRecord]] = {}

            for packet in window_packets:
                grouped.setdefault(packet.src_ip, []).append(packet)

            # Extract features for every source IP
            for src_ip, packets in grouped.items():

                flow = FlowFeatures(
                    src_ip=src_ip,
                    window_start=window_start,
                    window_end=window_end,
                    first_seen=packets[0].timestamp,
                    last_seen=packets[0].timestamp,
                )

                connections: Set[tuple] = set()

                for packet in packets:

                    # -------------------------
                    # Basic traffic statistics
                    # -------------------------

                    flow.total_packets += 1
                    flow.total_bytes += packet.length

                    # -------------------------
                    # Destination information
                    # -------------------------

                    flow.unique_destinations.add(packet.dst_ip)

                    if packet.dst_port is not None:
                        flow.unique_dst_ports.add(packet.dst_port)

                        connections.add(
                            (packet.dst_ip, packet.dst_port)
                        )

                    # -------------------------
                    # Protocol
                    # -------------------------

                    flow.protocols.add(packet.protocol)

                    # -------------------------
                    # SYN detection
                    # -------------------------

                    if (
                        packet.tcp_flags
                        and "S" in packet.tcp_flags
                        and "A" not in packet.tcp_flags
                    ):
                        flow.syn_count += 1

                    # -------------------------
                    # Timing information
                    # -------------------------

                    flow.first_seen = min(
                        flow.first_seen,
                        packet.timestamp
                    )

                    flow.last_seen = max(
                        flow.last_seen,
                        packet.timestamp
                    )

                    flow.timestamps.append(packet.timestamp)

                flow.connection_count = len(connections)

                # Store features for this source IP
                results.setdefault(src_ip, []).append(flow)

        # Move sliding window forward
        window_start += step

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python feature_extractor.py <pcap_file>")
        sys.exit(1)

    from traffic_parser import parse_pcap

    records = parse_pcap(sys.argv[1])

    features = extract_features(records)

    print(f"Found {len(features)} source IP(s)")

    for src_ip, windows in features.items():

        print(f"\nSource IP: {src_ip}")
        print(f"Windows: {len(windows)}")

        for window in windows[:3]:
            print(window.to_dict())