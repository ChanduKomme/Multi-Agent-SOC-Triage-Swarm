"""Read-only view of the (fictional) environment the agents investigate.

Author: Chandu Komme

Everything here is reference data an analyst would look up: the asset inventory,
the identity directory, threat intel, IP geolocation, detection-rule history and
the approved change calendar. Agents never touch these files directly; they go
through the MCP tool server, which is the only component that reads them.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

__author__ = "Chandu Komme"

DEFAULT_WORLD = Path(__file__).resolve().parent.parent / "data" / "world"


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class World:
    def __init__(self, root: str | Path = DEFAULT_WORLD) -> None:
        root = Path(root)

        def load(name):
            return json.loads((root / f"{name}.json").read_text(encoding="utf-8"))

        self.assets = {a["host"]: a for a in load("assets")}
        self.identities = {i["principal"]: i for i in load("identities")}
        self.intel = {i["indicator"].lower(): i for i in load("intel")}
        self.geo = load("geo")
        self.rules = {r["rule"]: r for r in load("rules")}
        self.changes = load("changes")

    # Each lookup returns a plain dict that always carries ``found``.
    def asset(self, host: str) -> dict:
        hit = self.assets.get(host)
        return {"found": True, **hit} if hit else {"found": False, "host": host}

    def identity(self, principal: str) -> dict:
        hit = self.identities.get(principal)
        return {"found": True, **hit} if hit else {"found": False, "principal": principal}

    def threat_intel(self, indicator: str) -> dict:
        hit = self.intel.get(indicator.lower())
        if hit:
            return {"found": True, **hit}
        return {"found": False, "indicator": indicator, "verdict": "unknown"}

    def geolocate(self, ip: str) -> dict:
        if ip.startswith(("10.", "192.168.", "172.16.")):
            return {"found": True, "ip": ip, "country": "internal", "asn": "RFC1918", "hosting": False}
        hit = self.geo.get(ip)
        return {"found": True, "ip": ip, **hit} if hit else {"found": False, "ip": ip}

    def rule(self, rule_id: str) -> dict:
        hit = self.rules.get(rule_id)
        return {"found": True, **hit} if hit else {"found": False, "rule": rule_id}

    def change_window(self, target: str, at: str) -> dict:
        """Is there an approved change covering ``target`` at time ``at``?"""
        when = parse_time(at)
        for change in self.changes:
            if change["target"] != target:
                continue
            if not parse_time(change["start"]) <= when <= parse_time(change["end"]):
                continue
            window = change.get("daily_window")
            if window:
                hhmm = when.strftime("%H:%M")
                if not window[0] <= hhmm <= window[1]:
                    continue
            return {"found": True, "approved": True, **change}
        return {"found": False, "approved": False, "target": target, "at": at}
