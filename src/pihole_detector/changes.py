"""Every change the detector makes to Pi-hole: applied, logged and undone here.

Two kinds, each with its own log:

- Telegram changes (/block, /name, /pause...) are lists of ops, logged to pihole_changes.jsonl. An op
  is a JSON list: ["add_domain", type, kind, domain], ["delete_domain", type, kind, domain],
  ["add_client" | "update_client", client, comment, groups], ["delete_client", client],
  ["blocking", enabled, timer]. A change's Undo button holds the inverse ops.
- Rotation sync moves a device's Clients entry onto its new private MAC, logged to
  client_changes.jsonl. `clients-undo` and the Telegram Undo button both undo it through here, so both
  follow one rule: only a device's newest change can be undone, since an older one would restore a
  MAC that a later sync already replaced.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from . import yearlog
from .rotation import Client, SyncPlan
from .sinks import when


class PiholeChanges:
    def __init__(self, cfg, api=None):
        self.cfg = cfg
        self.api = api  # PiholeApi; None while nothing may change Pi-hole

    # Telegram changes -----------------------------------------------------------------------
    def apply(self, ops: list, now: float, command: str) -> None:
        """Run the ops in order and log the ones that ran. Raises on the first one Pi-hole refuses."""
        done = []
        try:
            for op in ops:
                self._run(op, now)
                done.append(op)
        finally:
            if done:
                yearlog.append(self.cfg.pihole_changes_path, {"time": now, "command": command, "ops": done})

    def _run(self, op: list, now: float) -> None:
        name, *args = op
        if name == "add_domain":
            self.api.add_domain(*args, comment=f"Telegram, {when(now)}")
        elif name == "delete_domain":
            self.api.delete_domain(*args)
        elif name in ("add_client", "update_client"):
            entry = Client(mac=args[0].lower(), client=args[0], comment=args[1], groups=tuple(args[2]))
            (self.api.add_client if name == "add_client" else self.api.update_client)(entry)
        elif name == "delete_client":
            self.api.delete_client(args[0])
        elif name == "blocking":
            self.api.set_blocking(args[0], args[1])
        else:
            raise ValueError(f"unknown op {name}")

    # rotation sync --------------------------------------------------------------------------
    def apply_sync(self, plan: SyncPlan, name: str, now: float) -> tuple[list[Client], str | None]:
        """Add the new MAC, then delete the old ones; (deleted, error). Raises, logging nothing, when the
        add itself fails. A failed delete stops there and is logged with its error."""
        self.api.add_client(plan.add)
        deleted, error = [], None
        try:
            for entry in plan.delete:
                self.api.delete_client(entry.client)
                deleted.append(entry)
        except Exception as exc:
            error = str(exc)
        self._log_sync({"time": now, "name": name, "added": asdict(plan.add),
                        "deleted": [asdict(e) for e in deleted], "error": error})
        return deleted, error

    def pending_sync(self, change_time: float | None = None) -> tuple[dict | None, str | None]:
        """(change to undo, None) or (None, why not). No time: the newest change not yet undone."""
        records = self._read_syncs()
        undone = {r["undo_of"] for r in records if "undo_of" in r}
        open_ = [r for r in records if "added" in r and r["time"] not in undone]
        if change_time is None:
            return (open_[-1], None) if open_ else (None, "nothing to undo")
        change = next((r for r in open_ if r["time"] == change_time), None)
        if change is None:
            return None, "that change was already undone"
        name = change["name"].casefold()
        if any(r["name"].casefold() == name and r["time"] > change["time"] for r in open_):
            return None, f"there is a newer change for {change['name']}; undo that one first"
        return change, None

    def undo_sync(self, change: dict, now: float) -> None:
        """Remove the MAC the change added, re-add the ones it removed, and log the undo."""
        self.api.delete_client(change["added"]["client"])
        for entry in change["deleted"]:
            self.api.add_client(Client(**{**entry, "groups": tuple(entry["groups"])}))
        self._log_sync({"time": now, "undo_of": change["time"]})

    # client_changes.jsonl is not rolled over yearly: undo has to see last year's changes too.
    def _log_sync(self, record: dict) -> None:
        with Path(self.cfg.client_changes_path).open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def _read_syncs(self) -> list[dict]:
        path = Path(self.cfg.client_changes_path)
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
