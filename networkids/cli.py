"""Command-line entry point for offline NetworkIDS analysis."""
import argparse
import json
import sys
from .detectors import detect
from .inputs import read_pcap, read_suricata_eve
from .reporting import write_csv, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="networkids",
        description="Analyze authorized PCAP/PCAPNG captures or Suricata EVE JSON logs.",
    )
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--pcap", help="Path to a PCAP or PCAPNG capture")
    inputs.add_argument("--eve", help="Path to a Suricata EVE JSON log")
    parser.add_argument("--json-out", default="networkids-findings.json", help="JSON report path")
    parser.add_argument("--csv-out", default="networkids-findings.csv", help="CSV report path")
    parser.add_argument("--window", type=int, default=60, help="Detection window in seconds (default: 60)")
    parser.add_argument("--syn-scan-ports", type=int, default=12, help="Distinct TCP SYN destination ports to trigger scan finding")
    parser.add_argument("--fanout-destinations", type=int, default=20, help="Distinct flow destinations to trigger fan-out finding")
    parser.add_argument("--connection-burst", type=int, default=100, help="Flow events in window to trigger burst finding")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        events = list(read_pcap(args.pcap) if args.pcap else read_suricata_eve(args.eve))
        findings = detect(
            events,
            window_seconds=args.window,
            syn_scan_ports=args.syn_scan_ports,
            fanout_destinations=args.fanout_destinations,
            connection_burst=args.connection_burst,
        )
        write_json(findings, args.json_out)
        write_csv(findings, args.csv_out)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"networkids: error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps({
        "input_events": len(events),
        "findings": len(findings),
        "json_report": args.json_out,
        "csv_report": args.csv_out,
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
