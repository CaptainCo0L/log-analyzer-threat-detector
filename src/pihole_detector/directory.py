"""Who a device is: what to call it, which other MACs it has used, and finding it from what the owner typed.

A device is named, best first, by its Pi-hole Clients comment (by MAC, then by IP), the name discovery
saved for it, Pi-hole's own hostname for it, a vendor guess, and last its MAC. Every alert, report and
bot reply asks this module, so the order lives in one place.
"""

from __future__ import annotations

import ipaddress
import re

from .names import ipv4_of
from .namestore import MAC, NameStore, relabel
from .rotation import TRUSTED, device_macs


def name_key(text: str | None) -> str:
    """A name reduced to letters and digits, so "Aswins ipad" finds "Aswins-iPad"."""
    return re.sub(r"[^a-z0-9]", "", (text or "").casefold())


class Directory:
    def __init__(self, comments, names: NameStore):
        self._comments = comments  # () -> {MAC or IP: Clients comment}, re-read with the intel
        self.names = names
        self.ip_to_mac: dict[str, str] = {}

    def learn(self, devices) -> None:
        """Remember which MAC each IP belongs to, from a Pi-hole device snapshot."""
        for dev in devices:
            if dev.is_real_mac:
                for ip in dev.ips:
                    self.ip_to_mac[ip] = dev.hwaddr

    def name(self, mac: str | None, ip: str | None = None) -> str | None:
        """A name a person or discovery chose (comment, then saved name), or None."""
        comments = self._comments()
        return (mac and comments.get(mac)) or (ip and comments.get(ip)) or self.names.name(mac) or None

    def label(self, dev) -> str:
        """What to call a Pi-hole device: never empty."""
        return (self.name(dev.hwaddr, ipv4_of(dev)) or dev.name
                or (f"{dev.vendor} device" if dev.vendor else dev.hwaddr))

    def source(self, dev) -> str:
        """Where label(dev) came from, in words."""
        ip = ipv4_of(dev)
        comments = self._comments()
        if comments.get(dev.hwaddr) or (ip and comments.get(ip)):
            return "Clients comment"
        saved = self.names.entries.get(dev.hwaddr)
        if saved:
            return f"discovered ({saved['source']})"
        return "Pi-hole hostname" if dev.name else "vendor guess"

    def previous_mac(self, mac: str, name: str, source: str) -> str | None:
        """Another MAC this device used, if it answered with a trusted name saved for that MAC too.

        The same rule rotation sync uses, so an alert never calls a MAC "the same device" that sync
        would refuse to move. Any device can claim any name, so only mDNS/Bonjour names count.
        """
        if source not in TRUSTED:
            return None
        others = device_macs(self.names.entries, name, exclude=mac)
        return max(others, key=lambda m: self.names.entries[m].get("confirmed", 0), default=None)

    def relabel(self, records: list[dict]) -> list[dict]:
        """Alert records with the current name for their MAC (see namestore.relabel)."""
        return relabel(records, self.name)

    def find(self, query: str, devices) -> list:
        """Devices matching a MAC, an IP, or any name they go by, whole or in part."""
        q = query.strip().lower()
        if MAC.fullmatch(q):
            return [d for d in devices if d.hwaddr == q]
        try:
            ipaddress.ip_address(q)
            return [d for d in devices if q in d.ips]
        except ValueError:
            pass
        key = name_key(query)
        if not key:
            return []
        known = {d.hwaddr: self._name_keys(d) for d in devices}
        exact = [d for d in devices if key in known[d.hwaddr]]
        return exact or [d for d in devices if any(key in name for name in known[d.hwaddr])]

    def one_device(self, found) -> bool:
        """Do these matches all go by the same name (one device on several private MACs)?"""
        return len({name_key(self.label(d)) for d in found}) == 1

    def _name_keys(self, dev) -> set[str]:
        saved = self.names.entries.get(dev.hwaddr) or {}
        names = (self.label(dev), self._comments().get(dev.hwaddr), saved.get("name"), dev.name)
        return {key for name in names if (key := name_key(name))}

