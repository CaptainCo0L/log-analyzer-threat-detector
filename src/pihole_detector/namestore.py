"""Names found by discovery, saved between runs (data/names.json)."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path

from .names import SOURCES

log = logging.getLogger(__name__)


def best_probe(evidence: dict[str, str]) -> tuple[str, str] | None:
    """(name, source) from the most trusted probe that answered, or None."""
    return next(((evidence[s], s) for s in SOURCES if s in evidence), None)


class NameStore:
    """MAC -> {name, source, confirmed}. Another process (a manual `names --save`) may rewrite the
    file, so the service calls reload_if_changed() instead of holding a stale copy forever."""

    def __init__(self, path):
        self.path = Path(path)
        self.entries: dict[str, dict] = {}
        self._stamp = None
        self.reload_if_changed()

    def name(self, mac: str | None) -> str | None:
        entry = self.entries.get((mac or "").lower())
        return entry["name"] if entry else None

    def _file_stamp(self):
        try:
            st = self.path.stat()
        except OSError:
            return None
        return (st.st_mtime_ns, st.st_size)

    def reload_if_changed(self) -> bool:
        stamp = self._file_stamp()
        if stamp == self._stamp:
            return False
        self._stamp = stamp
        self.entries = {}
        if stamp is not None:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self.entries = {mac.lower(): e for mac, e in data.items()
                                if isinstance(e, dict) and e.get("name")}
            except (OSError, ValueError, AttributeError):
                log.warning("ignoring unreadable names file %s", self.path)
        return True

    def update(self, found: dict[str, tuple[str, str]], now: float) -> list[tuple[str, str | None, str]]:
        """Merge {mac: (name, source)}. Devices not in `found` keep their entry untouched, because a
        device that did not answer this time is not a device that is gone."""
        changes = []
        for mac, (name, source) in found.items():
            mac = mac.lower()
            old = self.entries.get(mac, {}).get("name")
            if old != name:
                changes.append((mac, old, name))
            self.entries[mac] = {"name": name, "source": source, "confirmed": now}
        return changes

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps(self.entries, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)  # a reader never sees a half-written file
        self._stamp = self._file_stamp()


MAC = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", re.I)


def mac_from_address(address: str) -> str | None:
    """The MAC out of an alert's "ip · mac" address field, lowercased."""
    found = MAC.search(address or "")
    return found.group(0).lower() if found else None


def relabel(records: list[dict], lookup) -> list[dict]:
    """Copies of alert records whose `client` is the current name for their MAC.

    Used when a report is displayed, so a name found after an alert fired still shows. The records
    on disk are never rewritten. Records with no MAC, or no better name, keep what they had.
    """
    out = []
    for record in records:
        mac = mac_from_address(record.get("address", ""))
        name = lookup(mac) if mac else None
        out.append({**record, "client": name} if name else record)
    return out
