"""alerts.jsonl: every alert, written once and read back by the digest, the bot and `report`.

Every reader goes through `read`, so a line that isn't a complete alert (bad JSON, or missing time,
severity, rule or client) is skipped the same way everywhere instead of crashing one of them.
The file rolls over yearly (see yearlog.py); reads span the archives.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import yearlog
from .model import Alert
from .namestore import record_mac


class AlertLog:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, alert: Alert) -> None:
        yearlog.append(self.path, alert.to_dict(), sort_keys=True)

    def read(self, start: float = 0, end: float = float("inf"), mac: str | None = None) -> list[dict]:
        """Alerts with start <= time <= end, oldest first; only one device's when `mac` is given."""
        return self.read_counted(start, end, mac)[0]

    def read_counted(self, start: float = 0, end: float = float("inf"),
                     mac: str | None = None) -> tuple[list[dict], int]:
        """read(), plus how many lines could not be read."""
        records, skipped = [], 0
        for path in yearlog.files(self.path, start):
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    if not line.strip():
                        continue
                    try:
                        record = json.loads(line)
                        when = float(record["time"])
                        record["severity"], record["rule"], record["client"]
                    except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                        skipped += 1
                        continue
                    if start <= when <= end and (mac is None or record_mac(record) == mac):
                        records.append(record)
        return records, skipped
