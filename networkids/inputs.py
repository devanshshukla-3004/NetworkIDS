"""Input adapters for offline PCAP files and Suricata EVE JSON logs."""
import json
from pathlib import Path
from typing import Iterator

from .models import NetworkEvent


def read_pcap(path: str | Path) -> Iterator[NetworkEvent]:
    """Yield normalized packet events from a PCAP/PCAPNG file using Scapy."""
    try:
        from scapy.all import IP, IPv6, TCP, UDP, PcapReader
    except ImportError as exc:
        raise RuntimeError("PCAP support requires Scapy. Install requirements.txt first.") from exc

    with PcapReader(str(path)) as reader:
        for packet in reader:
            if not (packet.haslayer(IP) or packet.haslayer(IPv6)):
                continue
            ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
            protocol = "unknown"
            dst_port = None
            flags = ""
            if packet.haslayer(TCP):
                protocol = "tcp"
                dst_port = int(packet[TCP].dport)
                flags = str(packet[TCP].flags)
            elif packet.haslayer(UDP):
                protocol = "udp"
                dst_port = int(packet[UDP].dport)

            yield NetworkEvent(
                timestamp=float(packet.time),
                src_ip=str(ip_layer.src),
                dst_ip=str(ip_layer.dst),
                dst_port=dst_port,
                protocol=protocol,
                tcp_flags=flags,
                event_type="packet",
                source="pcap",
            )


def read_suricata_eve(path: str | Path) -> Iterator[NetworkEvent]:
    """Yield normalized events from newline-delimited Suricata EVE JSON."""
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON in EVE log at line {line_number}: {exc.msg}") from exc

            event_type = str(record.get("event_type", "unknown"))
            alert = record.get("alert") or {}
            timestamp = record.get("timestamp")
            if not timestamp:
                continue
            # Suricata timestamps are ISO-8601. Convert them to Unix seconds.
            from datetime import datetime
            try:
                parsed_time = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00")).timestamp()
            except ValueError as exc:
                raise ValueError(f"Invalid timestamp in EVE log at line {line_number}") from exc

            proto = str(record.get("proto", "unknown")).lower()
            if proto not in {"tcp", "udp", "icmp", "icmpv6"}:
                proto = "unknown"
            try:
                dst_port = int(record["dest_port"]) if record.get("dest_port") is not None else None
            except (ValueError, TypeError):
                dst_port = None

            yield NetworkEvent(
                timestamp=parsed_time,
                src_ip=str(record.get("src_ip", "")),
                dst_ip=str(record.get("dest_ip", "")),
                dst_port=dst_port,
                protocol=proto,
                event_type=event_type,
                source="suricata_eve",
                signature=str(alert.get("signature", "")),
                raw=record,
            )
