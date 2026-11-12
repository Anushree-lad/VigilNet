
"""
main.py
-------
VigilNet main detection pipeline.
"""

import sys

from traffic_parser import parse_pcap
from feature_extractor import extract_features
from rules import run_rules
from risk_scorer import score_detections
from ai_analyzer import analyze
from report_generator import generate_report
from pdf_report_generator import generate_pdf_report

from alert_manager import (
    create_managed_alert,
    add_alert,
    load_alerts,
)

from alert_correlator import (
    correlate_alerts,
    print_incidents,
)

from incident_manager import get_incidents


def run_pipeline(pcap_path: str):

    print(
        f"\n=== VigilNet: analyzing {pcap_path} ===\n"
    )

    # -----------------------------------------
    # 1. Parse PCAP
    # -----------------------------------------

    records = parse_pcap(pcap_path)

    print(
        f"[1] Parsed {len(records)} IP packets"
    )

    capture_start = (
        records[0].timestamp
        if records
        else 0
    )

    # -----------------------------------------
    # 2. Extract Features
    # -----------------------------------------

    flows = extract_features(
        records,
        window_size=10.0,
        step=5.0,
    )

    print(
        f"[2] Extracted features for "
        f"{len(flows)} source IP(s)"
    )

    # -----------------------------------------
    # 3. Run Security Rules
    # -----------------------------------------

    detections = run_rules(flows)

    print(
        f"[3] Rule engine triggered "
        f"{len(detections)} detection(s)"
    )

    # -----------------------------------------
    # 4. Risk Scoring
    # -----------------------------------------

    assessments = score_detections(
        detections
    )

    print(
        f"[4] Risk-scored "
        f"{len(assessments)} suspicious source(s)"
    )

    # -----------------------------------------
    # 5. Alert Management
    # -----------------------------------------

    managed_alerts = 0
    duplicate_alerts = 0

    for ip, assessment in assessments.items():

        for detection in assessment.detections:

            alert = create_managed_alert(
                source_ip=detection.src_ip,
                alert_type=detection.rule,
                severity=detection.severity,
                message=detection.evidence,
                risk_score=assessment.score,
            )

            added = add_alert(alert)

            if added:
                managed_alerts += 1
            else:
                duplicate_alerts += 1

    print(
        f"[5] Managed alerts created: "
        f"{managed_alerts}"
    )

    if duplicate_alerts:

        print(
            f"[5] Duplicate alerts blocked: "
            f"{duplicate_alerts}"
        )

    # -----------------------------------------
    # 6. Alert Correlation
    # -----------------------------------------

    stored_alerts = load_alerts()

    incidents = correlate_alerts(
        stored_alerts
    )

    print(
        f"[6] Security incidents correlated: "
        f"{len(incidents)}"
    )

    # -----------------------------------------
    # 7. Incident Management
    # -----------------------------------------

    managed_incidents = get_incidents()

    print(
        f"[7] Incident management initialized: "
        f"{len(managed_incidents)} incident(s)"
    )

    # -----------------------------------------
    # 8. AI Analysis
    # -----------------------------------------

    ai_analysis = {}

    for ip, assessment in assessments.items():

        ai_analysis[ip] = analyze(
            assessment
        )

    print(
        f"[8] AI analysis completed for "
        f"{len(ai_analysis)} suspicious source(s)"
    )

    # -----------------------------------------
    # 9. Generate JSON Security Report
    # -----------------------------------------

    generate_report(
        assessments,
        output_file="vigilnet_report.json",
        total_packets=len(records),
        total_sources=len(flows),
        total_detections=len(detections),
        ai_analysis=ai_analysis,
    )

    print(
        "[9] JSON security report generated: "
        "vigilnet_report.json"
    )

    # -----------------------------------------
    # 10. Generate PDF Security Report
    # -----------------------------------------

    generate_pdf_report(
        assessments=assessments,
        output_file="vigilnet_report.pdf",
        total_packets=len(records),
        total_sources=len(flows),
        total_detections=len(detections),
        ai_analysis=ai_analysis,
    )

    print(
        "[10] PDF security report generated: "
        "vigilnet_report.pdf"
    )

    # -----------------------------------------
    # No suspicious activity
    # -----------------------------------------

    if not assessments:

        print(
            "No suspicious activity detected."
        )

        return

    # -----------------------------------------
    # Display Security Incidents
    # -----------------------------------------

    print_incidents(
        incidents
    )

    # -----------------------------------------
    # Display Detection Results
    # -----------------------------------------

    for ip, assessment in sorted(
        assessments.items(),
        key=lambda x: -x[1].score,
    ):

        print("-" * 60)

        print(
            f"Source IP:       "
            f"{assessment.src_ip}"
        )

        print(
            f"Risk Score:      "
            f"{assessment.score}/100 "
            f"({assessment.band})"
        )

        print(
            f"Rules Triggered: "
            f"{', '.join(assessment.triggered_rules)}"
        )

        # -------------------------------------
        # Detection Windows
        # -------------------------------------

        print("\nDetection Windows:")

        for detection in assessment.detections:

            start = (
                detection.window_start
                - capture_start
            )

            end = (
                detection.window_end
                - capture_start
            )

            print(
                f"  - {detection.rule}: "
                f"{start:.1f}s → {end:.1f}s"
            )

        # -------------------------------------
        # AI Analysis
        # -------------------------------------

        print("\nAI Analysis:")

        print(
            ai_analysis[assessment.src_ip]
        )

        print("-" * 60)
        print()


# =============================================
# Program Entry Point
# =============================================

if __name__ == "__main__":

    if len(sys.argv) != 2:

        print(
            "Usage: python main.py <pcap_file>"
        )

        sys.exit(1)

    run_pipeline(
        sys.argv[1]
    )