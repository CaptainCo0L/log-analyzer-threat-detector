"""Every change the detector makes to Pi-hole: applied, logged and undone here.

Two kinds, each with its own log:

- Telegram changes (/block, /name, /pause...) are lists of ops, logged to pihole_changes.jsonl
  (rolled over yearly) as an audit trail. Build ops with the functions below; an op is a JSON list
  so a change's Undo button can hold the inverse ops.
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
from .names import same_name
from .rotation import Client, SyncPlan
from .sinks import when
from .source import PiholeClient


# Ops, built here so the op format stays in this module. Each returns a JSON-ready list.
def add_domain(list_type: str, kind: str, domain: str) -> list:
    return ["add_domain", list_type, kind, domain]


def delete_domain(list_type: str, kind: str, domain: str) -> list:
    return ["delete_domain", list_type, kind, domain]


def set_blocking(enabled: bool, timer: int | None = None) -> list:
    return ["blocking", enabled, timer]


def add_client(client: str, comment: str, groups) -> list:
    return ["add_client", client, comment, list(groups)]


def update_client(client: str, comment: str, groups) -> list:
    return ["update_client", client, comment, list(groups)]


def delete_client(client: str) -> list:
    return ["delete_client", client]


class PiholeChanges:
    def __init__(self, cfg, api: PiholeClient | None = None):
        self.cfg = cfg
        self.api = api  # None while nothing may change Pi-hole

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

    @property
    def pihole(self) -> PiholeClient:
        if self.api is None:
            raise RuntimeError("no Pi-hole API given, so nothing may change Pi-hole")
        return self.api

    def _run(self, op: list, now: float) -> None:
        name, *args = op
        api = self.pihole
        if name == "add_domain":
            list_type, kind, domain = args
            api.add_domain(list_type, kind, domain, comment=f"Telegram, {when(now)}")
        elif name == "delete_domain":
            list_type, kind, domain = args
            api.delete_domain(list_type, kind, domain)
        elif name in ("add_client", "update_client"):
            entry = Client(mac=args[0].lower(), client=args[0], comment=args[1], groups=tuple(args[2]))
            (api.add_client if name == "add_client" else api.update_client)(entry)
        elif name == "delete_client":
            api.delete_client(args[0])
        elif name == "blocking":
            api.set_blocking(args[0], args[1])
        else:
            raise ValueError(f"unknown op {name}")

    # rotation sync --------------------------------------------------------------------------
    def apply_sync(self, plan: SyncPlan, name: str, now: float) -> tuple[list[Client], str | None]:
        """Add the new MAC, then delete the old ones; (deleted, error). Raises, logging nothing, when the
        add itself fails. A failed delete stops there and is logged with its error."""
        if plan.add is None:
            raise ValueError(f"nothing to sync: {plan.reason}")
        self.pihole.add_client(plan.add)
        deleted: list[Client] = []
        error = None
        try:
            for entry in plan.delete:
                self.pihole.delete_client(entry.client)
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
        if any(same_name(r["name"], change["name"]) and r["time"] > change["time"] for r in open_):
            return None, f"there is a newer change for {change['name']}; undo that one first"
        return change, None

    def undo_sync(self, change: dict, now: float) -> None:
        """Remove the MAC the change added, re-add the ones it removed, and log the undo."""
        self.pihole.delete_client(change["added"]["client"])
        for entry in change["deleted"]:
            self.pihole.add_client(Client(**{**entry, "groups": tuple(entry["groups"])}))
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
