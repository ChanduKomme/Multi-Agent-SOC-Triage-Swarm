"""Tamper-evident audit trail (hash chain).

Author: Chandu Komme

Every step of a run (tool call, finding, incident, action, decision) is written
as one JSON line. Each record stores the SHA-256 of the previous record, so
editing, deleting or reordering any line breaks verification from that point on.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

__author__ = "Chandu Komme"

GENESIS = "0" * 64


def _digest(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self, run_id: str) -> None:
        self.run_id = run_id
        self.records: list[dict] = []

    def add(self, actor: str, event: str, data: dict) -> dict:
        record = {"seq": len(self.records) + 1, "run_id": self.run_id,
                  "at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                  "actor": actor, "event": event, "data": data,
                  "prev": self.records[-1]["hash"] if self.records else GENESIS}
        record["hash"] = _digest(record)
        self.records.append(record)
        return record

    def write(self, path: str | Path) -> None:
        Path(path).write_text("".join(json.dumps(r, sort_keys=True) + "\n" for r in self.records), encoding="utf-8")


def verify(path: str | Path) -> tuple[bool, str]:
    prev = GENESIS
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for n, line in enumerate(lines, 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            return False, f"line {n}: not valid JSON"
        if record.get("seq") != n:
            return False, f"line {n}: sequence number {record.get('seq')} out of order"
        if record.get("prev") != prev:
            return False, f"line {n}: previous-hash link is broken"
        if record.get("hash") != _digest(record):
            return False, f"line {n}: content does not match its hash"
        prev = record["hash"]
    return True, f"{len(lines)} records verified, head {prev[:16]}"
