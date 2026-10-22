"""Report writers for NetworkIDS findings."""
import csv
import json
from pathlib import Path
from .models import Finding


def write_json(findings: list[Finding], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps([item.to_dict() for item in findings], indent=2), encoding="utf-8")


def write_csv(findings: list[Finding], path: str | Path) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fields = ["rule_id", "title", "severity", "confidence", "src_ip",
              "first_seen", "last_seen", "event_count", "evidence", "recommendation"]
    with target.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for finding in findings:
            row = finding.to_dict()
            row["evidence"] = json.dumps(row["evidence"], sort_keys=True)
            writer.writerow(row)
