"""Rotation sync: which Pi-hole Clients entries follow a device onto its new private Wi-Fi MAC.

Pure decisions, no I/O. A device is the set of MACs saved in names.json under one mDNS/Bonjour name.
Any device can claim any name, so the rules stay narrow: only private MACs, only names a device gave
over mDNS/Bonjour, only entries saved under that same name, and never a burned-in MAC.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field

from .names import same_name

TRUSTED = ("mDNS", "Bonjour")
DEFAULT_GROUP = 0
UNDO = "sudo docker exec pihole-detector python -m pihole_detector clients-undo"


@dataclass(frozen=True)
class Client:
    """One Pi-hole Clients entry. `client` is the string Pi-hole stores (and wants back in URLs)."""

    mac: str
    client: str
    comment: str
    groups: tuple[int, ...]


@dataclass
class SyncPlan:
    add: Client | None = None
    delete: list[Client] = field(default_factory=list)
    reason: str | None = None  # why nothing is done


def is_private(mac: str) -> bool:
    return len(mac) == 17 and int(mac[:2], 16) & 2 == 2


def device_macs(names: dict[str, dict], name: str, exclude: str = "") -> set[str]:
    """The MACs saved in names.json under this mDNS/Bonjour name: one device, as far as we can tell."""
    return {mac for mac, e in names.items()
            if mac != exclude and e.get("source") in TRUSTED and same_name(e.get("name"), name)}


def plan_sync(new_mac: str, name: str, source: str, clients: list[Client], names: dict[str, dict],
              last_seen: dict[str, float], keep: int = 2) -> SyncPlan:
    """Add `new_mac` with the device's newest entry's comment and groups; keep its `keep` most recently
    seen MACs and delete the rest (private ones only)."""
    new_mac = new_mac.lower()
    if source not in TRUSTED:
        return SyncPlan(reason=f"name came from {source}, only mDNS/Bonjour names are trusted")
    if not is_private(new_mac):
        return SyncPlan(reason="not a private MAC")
    if any(c.mac == new_mac for c in clients):
        return SyncPlan(reason="already a Pi-hole client")
    device = device_macs(names, name, exclude=new_mac)
    entries = [c for c in clients if c.mac in device]
    if not entries:
        return SyncPlan(reason=f"no Pi-hole Clients entry for {name} to copy")
    if len({frozenset(c.groups) for c in entries}) > 1:
        return SyncPlan(reason=f"groups differ between {name}'s entries, so it is unclear which to copy")
    entries.sort(key=lambda c: last_seen.get(c.mac, 0), reverse=True)
    newest = entries[0]
    add = Client(mac=new_mac, client=new_mac, comment=newest.comment,
                 groups=tuple(sorted({DEFAULT_GROUP, *newest.groups})))
    delete = [c for c in entries[max(keep - 1, 0):] if is_private(c.mac)]
    return SyncPlan(add=add, delete=delete)


def format_sync(name: str, added: Client, deleted: list[Client], groups: dict[int, str],
                error: str | None = None) -> str:
    """The Telegram message for one sync: what was added and removed, and how to undo it."""
    def group_names(entry):
        return ", ".join(groups.get(g, str(g)) for g in entry.groups)

    lines = [f"🔁 <b>{html.escape(name)} is on a new private Wi-Fi MAC</b>", "",
             f"Added <code>{added.mac}</code> to Pi-hole Clients as \"{html.escape(added.comment)}\" "
             f"({html.escape(group_names(added))})"]
    lines += [f"Removed <code>{c.mac}</code> \"{html.escape(c.comment)}\" ({html.escape(group_names(c))})"
              for c in deleted]
    if error:
        lines += ["", f"⚠️ Stopped part-way: {html.escape(error)}"]
    lines += ["", f"Undo: <code>{UNDO}</code>"]
    return "\n".join(lines)
