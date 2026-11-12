"""
risk_scorer.py
--------------
Converts rule detections into a single 0-100 risk score.

Duplicate detections from overlapping time windows are counted only once.
"""

from dataclasses import dataclass
from typing import List, Dict

from rules import Detection


BANDS = [
    (0, 29, "LOW"),
    (30, 59, "MEDIUM"),
    (60, 79, "HIGH"),
    (80, 100, "CRITICAL"),
]


@dataclass
class RiskAssessment:
    src_ip: str
    score: int
    band: str
    triggered_rules: List[str]
    detections: List[Detection]


def score_to_band(score: int) -> str:

    for low, high, band in BANDS:

        if low <= score <= high:
            return band

    return "CRITICAL"


def score_detections(detections: List[Detection]) -> Dict[str, RiskAssessment]:

    # Group detections by source IP
    by_ip: Dict[str, List[Detection]] = {}

    for detection in detections:

        if detection.src_ip not in by_ip:
            by_ip[detection.src_ip] = []

        by_ip[detection.src_ip].append(detection)

    results: Dict[str, RiskAssessment] = {}

    # Process each source IP
    for ip, dets in by_ip.items():

        # Remove duplicate rules caused by overlapping windows
        unique_detections: Dict[str, Detection] = {}

        for detection in dets:

            if detection.rule not in unique_detections:
                unique_detections[detection.rule] = detection

        final_detections = list(unique_detections.values())

        # Calculate score
        raw_score = 0

        for detection in final_detections:
            raw_score += detection.weight

        score = min(raw_score, 100)

        # Create assessment
        results[ip] = RiskAssessment(
            src_ip=ip,
            score=score,
            band=score_to_band(score),
            triggered_rules=[
                detection.rule
                for detection in final_detections
            ],
            detections=final_detections,
        )

    return results