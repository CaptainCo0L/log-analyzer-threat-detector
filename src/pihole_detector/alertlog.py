"""alerts.jsonl: every alert, written once and read back by the digest, the bot and `report`.

Every reader goes through `read`, so a line that isn't a complete alert (bad JSON, or missing time,
severity, rule or label) is skipped the same way everywhere instead of crashing one of them, and a
line written before alerts named their device in fields (`upgrade`) reads like a new one.
The file rolls over yearly (see yearlog.py); reads span the archives.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import yearlog
from .model import Alert
from .namestore import MAC


def upgrade(record: dict) -> dict:
    """A record in today's shape. Older ones have `client` and an `address` of "ip · mac", and only
    their dedup key names the device. Early ones have no address: Pi-hole labelled such clients
    "(ip, mac)", which still holds the MAC."""
    if "label" in record:
        return record
    old = dict(record)
    label, address = old.pop("client"), old.pop("address", None) or ""
    found = MAC.search(address) or MAC.search(str(label))
    mac = found.group(0).lower() if found else ""
    ips = [part for part in address.split(" · ") if part and not MAC.fullmatch(part)]
    key = str(old.get("dedup") or "").split("|")
    return {**old, "label": label, "mac": mac, "ips": ips, "device": key[1] if len(key) > 1 else mac}


class AlertLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, alert: Alert) -> None:
        yearlog.append(self.path, alert.to_dict(), sort_keys=True)

    def read(self, start: float = 0, end: float = float("inf")) -> list[dict]:
        """Alerts with start <= time <= end, oldest first."""
        return self.read_counted(start, end)[0]

    def read_counted(self, start: float = 0, end: float = float("inf")) -> tuple[list[dict], int]:
        """read(), plus how many lines could not be read."""
        records, skipped = [], 0
        for path in yearlog.files(self.path, start):
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        record = upgrade(json.loads(line))
                        when = float(record["time"])
                        record["severity"], record["rule"]
                    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                        skipped += 1
                        continue
                    if start <= when <= end:
                        records.append(record)
        return records, skipped
