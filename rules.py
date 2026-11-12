"""
rules.py
--------
Security rules engine for VigilNet.

Rules are threshold-based (zero ML).
Each rule checks the behavior of a source IP
inside a time window.
"""

from dataclasses import dataclass
from typing import List

from feature_extractor import FlowFeatures


# ============================================================
# TUNABLE THRESHOLDS
# ============================================================

PORT_SCAN_UNIQUE_PORTS = 20
PORT_SCAN_WINDOW_SECONDS = 60

SYN_FLOOD_SYN_COUNT = 50
SYN_FLOOD_WINDOW_SECONDS = 30

DDOS_PACKET_RATE = 200
DDOS_MIN_PACKETS = 500

RECON_UNIQUE_HOSTS = 15
RECON_WINDOW_SECONDS = 60

BEACONING_MIN_PACKETS = 10
BEACONING_MAX_UNIQUE_DESTS = 2
BEACONING_MAX_INTERVAL_CV = 0.3


# ============================================================
# DETECTION DATA CLASS
# ============================================================

@dataclass
class Detection:
    src_ip: str
    rule: str
    severity: str
    evidence: str
    weight: int

    # Time window where detection occurred
    window_start: float = 0.0
    window_end: float = 0.0


# ============================================================
# PORT SCAN
# ============================================================

def detect_port_scan(f: FlowFeatures) -> List[Detection]:

    ports = len(f.unique_dst_ports)

    if ports >= PORT_SCAN_UNIQUE_PORTS and f.duration <= PORT_SCAN_WINDOW_SECONDS:

        return [
            Detection(
                src_ip=f.src_ip,
                rule="Port Scan",
                severity="HIGH",
                evidence=(
                    f"{f.src_ip} contacted {ports} unique ports "
                    f"within {f.duration:.1f}s."
                ),
                weight=30,
                window_start=f.window_start,
                window_end=f.window_end,
            )
        ]

    return []


# ============================================================
# SYN FLOOD
# ============================================================

def detect_syn_flood(f: FlowFeatures) -> List[Detection]:

    if (
        f.syn_count >= SYN_FLOOD_SYN_COUNT
        and f.duration <= SYN_FLOOD_WINDOW_SECONDS
    ):

        return [
            Detection(
                src_ip=f.src_ip,
                rule="SYN Flood",
                severity="CRITICAL",
                evidence=(
                    f"{f.src_ip} sent {f.syn_count} "
                    f"unacknowledged SYN packets "
                    f"in {f.duration:.1f}s."
                ),
                weight=40,
                window_start=f.window_start,
                window_end=f.window_end,
            )
        ]

    return []


# ============================================================
# DDOS-LIKE TRAFFIC
# ============================================================

def detect_ddos(f: FlowFeatures) -> List[Detection]:

    if f.total_packets >= DDOS_MIN_PACKETS and f.duration > 0:

        rate = f.total_packets / f.duration

        if rate >= DDOS_PACKET_RATE:

            return [
                Detection(
                    src_ip=f.src_ip,
                    rule="DDoS-like Traffic",
                    severity="CRITICAL",
                    evidence=(
                        f"{f.src_ip} sent {f.total_packets} "
                        f"packets at approximately "
                        f"{rate:.0f} packets/sec."
                    ),
                    weight=40,
                    window_start=f.window_start,
                    window_end=f.window_end,
                )
            ]

    return []


# ============================================================
# NETWORK RECONNAISSANCE
# ============================================================

def detect_reconnaissance(f: FlowFeatures) -> List[Detection]:

    hosts = len(f.unique_destinations)

    if (
        hosts >= RECON_UNIQUE_HOSTS
        and f.duration <= RECON_WINDOW_SECONDS
    ):

        return [
            Detection(
                src_ip=f.src_ip,
                rule="Network Reconnaissance",
                severity="MEDIUM",
                evidence=(
                    f"{f.src_ip} probed {hosts} distinct hosts "
                    f"within {f.duration:.1f}s."
                ),
                weight=20,
                window_start=f.window_start,
                window_end=f.window_end,
            )
        ]

    return []


# ============================================================
# BEACONING
# ============================================================

def _interval_coefficient_of_variation(
    timestamps: List[float],
) -> float:

    if len(timestamps) < 3:
        return float("inf")

    ts = sorted(timestamps)

    gaps = [
        ts[i + 1] - ts[i]
        for i in range(len(ts) - 1)
    ]

    mean_gap = sum(gaps) / len(gaps)

    if mean_gap == 0:
        return float("inf")

    variance = (
        sum((gap - mean_gap) ** 2 for gap in gaps)
        / len(gaps)
    )

    std_dev = variance ** 0.5

    return std_dev / mean_gap


def detect_beaconing(f: FlowFeatures) -> List[Detection]:
    """
    Detect periodic automated callback traffic.

    Beaconing should not be triggered when the same
    traffic already looks like port scanning or SYN flooding.
    """

    dests = len(f.unique_destinations)
    ports = len(f.unique_dst_ports)

    # Too little traffic or too many destinations
    if (
        f.total_packets < BEACONING_MIN_PACKETS
        or not (0 < dests <= BEACONING_MAX_UNIQUE_DESTS)
    ):
        return []

    # Avoid confusing port scans with beaconing
    if ports >= PORT_SCAN_UNIQUE_PORTS:
        return []

    # Avoid confusing SYN floods with beaconing
    if f.syn_count >= SYN_FLOOD_SYN_COUNT:
        return []

    cv = _interval_coefficient_of_variation(
        f.timestamps
    )

    if cv <= BEACONING_MAX_INTERVAL_CV:
        return [
            Detection(
                src_ip=f.src_ip,
                rule="Beaconing",
                severity="MEDIUM",
                evidence=(
                    f"{f.src_ip} sent "
                    f"{f.total_packets} packets "
                    f"to only {dests} destination(s) "
                    f"at suspiciously regular intervals "
                    f"(variation score {cv:.2f}), "
                    f"consistent with automated "
                    f"callback traffic."
                ),
                weight=15,
                window_start=f.window_start,
                window_end=f.window_end,
            )
        ]

    return []


# ============================================================
# ALL RULES
# ============================================================

ALL_RULES = [
    detect_port_scan,
    detect_syn_flood,
    detect_ddos,
    detect_reconnaissance,
    detect_beaconing,
]


# ============================================================
# RULE ENGINE
# ============================================================

def run_rules(flows: dict) -> List[Detection]:
    """
    Runs every security rule against every
    time window.
    """

    detections: List[Detection] = []

    for src_ip, windows in flows.items():

        for flow in windows:

            for rule_fn in ALL_RULES:

                detections.extend(
                    rule_fn(flow)
                )

    return detections