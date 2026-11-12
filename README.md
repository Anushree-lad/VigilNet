# VigilNet

AI-assisted detection of cyber threats in unidirectional IP traffic.
Rule-based detection (zero ML) + a local Ollama model that explains
each finding like a security analyst would.

## How it works

```
PCAP file
   -> traffic_parser.py     (Scapy: reads packets, extracts fields)
   -> feature_extractor.py  (groups packets into per-source-IP flow features)
   -> rules.py               (threshold-based detection: port scan, SYN flood,
                              DDoS-like traffic, reconnaissance, beaconing)
   -> risk_scorer.py         (sums rule weights into a 0-100 score + band)
   -> ai_analyzer.py         (Ollama explains the finding; falls back to a
                              template if Ollama isn't running)
   -> main.py                (prints the full report)
```

## Setup

```bash
pip install scapy --break-system-packages
```

Optional (for real AI explanations instead of the fallback template):

```bash
# install Ollama: https://ollama.com
ollama pull llama3.2
ollama serve
```

## Usage

Generate synthetic test traffic (no real capture needed):

```bash
python generate_test_traffic.py
```

Run the full pipeline:

```bash
python main.py sample_traffic.pcap
```

To analyze a real capture, just point it at any `.pcap` / `.pcapng` file:

```bash
python main.py path/to/your_capture.pcap
```

## Detection rules (current)

| Rule | Trigger condition | Weight |
|---|---|---|
| Port Scan | ≥20 unique dst ports within 60s | 30 |
| SYN Flood | ≥50 unacked SYNs within 30s | 40 |
| DDoS-like Traffic | ≥500 packets at ≥200 pkts/sec | 40 |
| Reconnaissance | ≥15 unique destination IPs within 60s | 20 |
| Beaconing | ≤2 destinations, ≥10 packets, low timing variance (regular intervals) | 15 |

Risk score = sum of triggered rule weights (capped at 100).
Bands: 0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL.

All thresholds are tunable constants at the top of `rules.py` -
adjust them once you test against your own traffic baseline.

## Known limitations (be upfront about these in your report)

- Thresholds are hand-picked, not learned from real traffic - expect
  false positives/negatives until tuned against your target network.
- Groups traffic by source IP with no time-windowing yet, so a long
  capture mixing benign and malicious behavior from the same IP over
  hours would blend together. Add sliding time windows for production use.
- Beaconing detection uses timing regularity (coefficient of variation)
  as a proxy for C2 callback behavior - real malware often jitters its
  beacon interval specifically to evade this kind of check.
- Ollama explanations are only as good as the prompt/model - treat them
  as an analyst aid, not ground truth.

## Not built yet (planned next)

- Dashboard (React) and REST API (FastAPI) for live browsing of results
- SQLite storage for scan history
- PDF report export (ReportLab)
- Live capture support (currently offline PCAP only)

## Project structure

```
vigilnet/
├── traffic_parser.py       # Scapy-based PCAP reader
├── feature_extractor.py    # per-source-IP flow feature aggregation
├── rules.py                 # threshold-based detection rules
├── risk_scorer.py            # risk score + band calculation
├── ai_analyzer.py             # Ollama-based explanation (with fallback)
├── generate_test_traffic.py    # synthetic PCAP generator for testing
├── main.py                      # pipeline orchestrator / CLI entrypoint
└── README.md
```
