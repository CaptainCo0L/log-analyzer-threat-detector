"""data/client_changes.jsonl: every rotation sync change to Pi-hole Clients, and undoing one.

Shared by `clients-undo` and the Telegram Undo button, so both follow the same rule: only a device's
newest change can be undone, since an older one would restore a MAC a later sync already replaced.
"""

from __future__ import annotations

import json
from pathlib import Path

from .rotation import Client


def read(path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def pick(records: list[dict], change_time: float | None = None) -> tuple[dict | None, str | None]:
    """(change to undo, None) or (None, why not). No time: the newest change not yet undone."""
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


def undo(change: dict, api, path, now: float) -> None:
    """Remove the MAC the change added, re-add the ones it removed, and log the undo."""
    api.delete_client(change["added"]["client"])
    for entry in change["deleted"]:
        api.add_client(Client(**{**entry, "groups": tuple(entry["groups"])}))
    with Path(path).open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"time": now, "undo_of": change["time"]}) + "\n")
