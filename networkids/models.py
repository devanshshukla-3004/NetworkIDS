"""Data models shared by input adapters and detection rules."""
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class NetworkEvent:
    timestamp: float
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int | None = None
    protocol: str = "unknown"
    tcp_flags: str = ""
    event_type: str = "packet"
    source: str = ""
    signature: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    src_ip: str
    first_seen: float
    last_seen: float
    event_count: int
    evidence: dict[str, Any]
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
