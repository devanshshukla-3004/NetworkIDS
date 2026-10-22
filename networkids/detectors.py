"""Stateful detection rules that operate on normalized observed events."""
from collections import defaultdict, deque
from .models import Finding, NetworkEvent


def detect(events: list[NetworkEvent], *, window_seconds: int = 60,
           syn_scan_ports: int = 12, fanout_destinations: int = 20,
           connection_burst: int = 100) -> list[Finding]:
    """Analyze observed events and return findings; no synthetic alerts are added."""
    if window_seconds < 1:
        raise ValueError("window_seconds must be at least 1")
    if syn_scan_ports < 2 or fanout_destinations < 2 or connection_burst < 2:
        raise ValueError("detection thresholds must be at least 2")

    findings: list[Finding] = []
    # Explicit Suricata alert records are retained as findings with their source evidence.
    for event in events:
        if event.event_type == "alert" and event.signature:
            alert = event.raw.get("alert", {})
            findings.append(Finding(
                rule_id=str(alert.get("signature_id", "SURICATA-ALERT")),
                title=event.signature,
                severity=_suricata_severity(alert.get("severity")),
                confidence="high",
                src_ip=event.src_ip,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                event_count=1,
                evidence={"source": event.source, "signature": event.signature,
                          "destination_ip": event.dst_ip, "destination_port": event.dst_port},
                recommendation="Review the original Suricata alert, surrounding flow records, and endpoint telemetry.",
            ))

    # Packet-level SYN scan: count distinct destination ports per source within a sliding window.
    by_source: dict[str, list[NetworkEvent]] = defaultdict(list)
    for event in events:
        if event.src_ip and event.protocol == "tcp" and "S" in event.tcp_flags and "A" not in event.tcp_flags:
            if event.dst_port is not None:
                by_source[event.src_ip].append(event)

    for src_ip, source_events in by_source.items():
        source_events.sort(key=lambda e: e.timestamp)
        active: deque[NetworkEvent] = deque()
        counts: dict[int, int] = defaultdict(int)
        reported: set[tuple[int, int]] = set()
        for event in source_events:
            while active and event.timestamp - active[0].timestamp > window_seconds:
                expired = active.popleft()
                counts[expired.dst_port] -= 1
                if counts[expired.dst_port] <= 0:
                    del counts[expired.dst_port]
            active.append(event)
            counts[event.dst_port] += 1
            ports = sorted(counts)
            if len(ports) >= syn_scan_ports:
                bucket = (int(event.timestamp // window_seconds), len(ports))
                if bucket not in reported:
                    findings.append(Finding(
                        rule_id="NIDS-TCP-SYN-SCAN",
                        title="Possible TCP SYN port scan",
                        severity="high",
                        confidence="medium",
                        src_ip=src_ip,
                        first_seen=active[0].timestamp,
                        last_seen=event.timestamp,
                        event_count=len(active),
                        evidence={"distinct_destination_ports": ports,
                                  "destination_port_count": len(ports),
                                  "window_seconds": window_seconds,
                                  "observed_packets": len(active)},
                        recommendation="Validate whether the source is an approved scanner; inspect target hosts and firewall logs.",
                    ))
                    reported.add(bucket)

    # Flow/EVE fan-out and bursts: these require records with a source and timestamp.
    by_source_time: dict[str, list[NetworkEvent]] = defaultdict(list)
    for event in events:
        if event.src_ip and event.event_type in {"flow", "netflow", "http", "dns", "tls"}:
            by_source_time[event.src_ip].append(event)

    for src_ip, source_events in by_source_time.items():
        source_events.sort(key=lambda e: e.timestamp)
        left = 0
        for right, event in enumerate(source_events):
            while event.timestamp - source_events[left].timestamp > window_seconds:
                left += 1
            batch = source_events[left:right + 1]
            destinations = {item.dst_ip for item in batch if item.dst_ip}
            if len(destinations) >= fanout_destinations:
                findings.append(Finding(
                    rule_id="NIDS-DESTINATION-FANOUT",
                    title="Unusual destination fan-out",
                    severity="medium",
                    confidence="low",
                    src_ip=src_ip,
                    first_seen=batch[0].timestamp,
                    last_seen=event.timestamp,
                    event_count=len(batch),
                    evidence={"distinct_destinations": len(destinations),
                              "window_seconds": window_seconds},
                    recommendation="Compare destination diversity with the host's normal role and review DNS/proxy/flow telemetry.",
                ))
                break
            if len(batch) >= connection_burst:
                findings.append(Finding(
                    rule_id="NIDS-CONNECTION-BURST",
                    title="High connection-event volume",
                    severity="medium",
                    confidence="low",
                    src_ip=src_ip,
                    first_seen=batch[0].timestamp,
                    last_seen=event.timestamp,
                    event_count=len(batch),
                    evidence={"event_count": len(batch), "window_seconds": window_seconds},
                    recommendation="Check whether the source is a scanner, busy service, health check, or unexpected automated client.",
                ))
                break

    # Stable ordering makes reports and tests reproducible.
    return sorted(findings, key=lambda item: (item.first_seen, item.rule_id, item.src_ip))


def _suricata_severity(value: object) -> str:
    try:
        severity = int(value)
    except (TypeError, ValueError):
        return "medium"
    return {1: "critical", 2: "high", 3: "medium"}.get(severity, "low")
