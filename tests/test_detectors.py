import json
from datetime import datetime, timezone
from pathlib import Path

from networkids.detectors import detect
from networkids.inputs import read_suricata_eve
from networkids.models import NetworkEvent
from networkids.reporting import write_csv, write_json


def test_detects_syn_scan_from_observed_packet_events():
    events = [
        NetworkEvent(timestamp=100 + i, src_ip="192.0.2.10", dst_ip="198.51.100.5",
                     dst_port=port, protocol="tcp", tcp_flags="S", source="pcap")
        for i, port in enumerate(range(20, 32))
    ]
    findings = detect(events, syn_scan_ports=10)
    scan = next(item for item in findings if item.rule_id == "NIDS-TCP-SYN-SCAN")
    assert scan.src_ip == "192.0.2.10"
    assert scan.evidence["destination_port_count"] >= 10


def test_ack_packets_do_not_trigger_syn_scan():
    events = [
        NetworkEvent(timestamp=100 + i, src_ip="192.0.2.10", dst_ip="198.51.100.5",
                     dst_port=port, protocol="tcp", tcp_flags="SA", source="pcap")
        for i, port in enumerate(range(20, 40))
    ]
    assert not detect(events, syn_scan_ports=5)


def test_reads_suricata_alert_and_preserves_signature(tmp_path: Path):
    stamp = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    log = tmp_path / "eve.json"
    log.write_text(json.dumps({
        "timestamp": stamp, "event_type": "alert", "src_ip": "192.0.2.4",
        "dest_ip": "198.51.100.8", "dest_port": 443, "proto": "TCP",
        "alert": {"signature": "Test signature", "signature_id": 1234, "severity": 2}
    }) + "\n", encoding="utf-8")
    events = list(read_suricata_eve(log))
    findings = detect(events)
    assert len(findings) == 1
    assert findings[0].title == "Test signature"
    assert findings[0].severity == "high"


def test_writes_json_and_csv_reports(tmp_path: Path):
    event = NetworkEvent(timestamp=100, src_ip="192.0.2.10", dst_ip="198.51.100.5",
                         dst_port=22, protocol="tcp", tcp_flags="S")
    findings = detect([event], syn_scan_ports=2)
    json_path, csv_path = tmp_path / "out.json", tmp_path / "out.csv"
    write_json(findings, json_path)
    write_csv(findings, csv_path)
    assert json.loads(json_path.read_text(encoding="utf-8")) == []
    assert "rule_id" in csv_path.read_text(encoding="utf-8")
