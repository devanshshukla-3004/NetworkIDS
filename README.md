# NetworkIDS

**Network Intrusion Detection System — offline defensive analysis**

NetworkIDS is a Python CLI for analyzing authorized packet captures and Suricata EVE JSON logs. It normalizes observed network evidence, applies transparent detection rules, and exports findings to JSON and CSV. It does not fabricate traffic or automatically block hosts.

## Current capabilities

- Read PCAP/PCAPNG files using Scapy.
- Read newline-delimited Suricata EVE JSON records.
- Detect TCP SYN scan patterns from observed packet flags and distinct destination ports.
- Detect destination fan-out and high event volume in supported Suricata flow-style records.
- Preserve existing Suricata alert signatures and severity.
- Export evidence-bearing findings to JSON and CSV.
- Run unit tests locally and in GitHub Actions.

## Quick start

Python 3.11+ is recommended.

```bash
python -m venv .venv
# Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Analyze an authorized packet capture:

```bash
python -m networkids --pcap path/to/capture.pcap --json-out reports/findings.json --csv-out reports/findings.csv
```

Analyze a Suricata EVE log:

```bash
python -m networkids --eve path/to/eve.json --json-out reports/findings.json --csv-out reports/findings.csv
```

Tune detection thresholds when appropriate:

```bash
python -m networkids --pcap path/to/capture.pcap --window 60 --syn-scan-ports 12
```

Run tests:

```bash
python -m pip install pytest
pytest -q
```

## Detection rules

| Rule ID | Evidence used | Initial interpretation |
| --- | --- | --- |
| `NIDS-TCP-SYN-SCAN` | Source sends TCP SYN packets to many distinct destination ports inside a sliding time window | Possible port scan; validate against approved scanners and network context |
| `NIDS-DESTINATION-FANOUT` | A source appears in flow-style events involving many distinct destinations in a window | Unusual destination diversity; investigate host role and surrounding telemetry |
| `NIDS-CONNECTION-BURST` | High volume of supported flow-style events from one source in a window | Potential burst; may also be normal service or automation activity |
| Suricata alert signature | Existing `event_type: alert` record and its alert metadata | Preserve and report the supplied Suricata detection |

Thresholds are heuristics, not proof of compromise. Findings include evidence and investigation guidance so an analyst can validate them.

## Input notes and limitations

- PCAP detection requires packets to contain the relevant IP/TCP headers. SYN-scan logic uses TCP flags and destination ports.
- Fan-out and connection-burst rules currently use Suricata event types `flow`, `netflow`, `http`, `dns`, and `tls`. These are event-volume heuristics and need tuning for each environment.
- EVE timestamps are parsed from ISO-8601 values. Malformed JSON or timestamps produce an explicit error instead of being silently accepted.
- This initial version is offline-first. It does not capture live interfaces, inject packets, or block traffic.
- Test fixtures validate the logic; they are not evidence of real-world detection performance. Validate against authorized captures and document false positives before operational use.

## Responsible use

Only analyze network captures and logs you own or are explicitly authorized to inspect. Keep sensitive packet captures and reports out of public commits; the repository ignores common `.pcap` and `.pcapng` files by default.

## Roadmap

- Add broader protocol-aware rules and configurable rule profiles.
- Add representative sanitized PCAP fixtures and integration tests.
- Improve performance for large captures and report rule-level statistics.
- Evaluate detections against labeled captures and document precision/recall before making performance claims.
