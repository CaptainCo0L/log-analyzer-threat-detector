"""Who a device is: what to call it, which other MACs it has used, and finding it from what the owner typed.

A device is named, best first, by its Pi-hole Clients comment (by MAC, then by IP), the name discovery
saved for it, Pi-hole's own hostname for it, a vendor guess, and last its MAC or IP. Every alert, report and
bot reply asks this module, so the order lives in one place.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Callable

from .model import MAC, Device
from .names import comment_for, ipv4_of, name_key
from .namestore import NameStore, relabel
from .rotation import TRUSTED, device_macs


@dataclass(frozen=True)
class Found:
    """One Device that matched what the owner typed, with every MAC of it Pi-hole lists."""

    device: str                 # its identity, state.device_of
    macs: tuple[Device, ...]    # newest lookup first
    label: str

    @property
    def current(self) -> Device:
        """The MAC it last looked something up from."""
        return self.macs[0]


class Directory:
    def __init__(self, comments, names: NameStore, device_of: Callable[[str], str] = lambda mac: mac):
        self._comments = comments  # () -> {MAC or IP: Clients comment}, re-read with the intel
        self.names = names
        self.device_of = device_of  # MAC -> the device's identity (state.device_of)
        self.ip_to_mac: dict[str, str] = {}
        self._vendors: dict[str, str | None] = {}

    def learn(self, devices) -> None:
        """Remember which MAC each IP belongs to, from a Pi-hole device snapshot."""
        for dev in devices:
            if dev.is_real_mac:
                self._vendors[dev.hwaddr] = dev.vendor
                for ip in dev.ips:
                    self.ip_to_mac[ip] = dev.hwaddr

    def name(self, mac: str | None, ip: str | None = None) -> str | None:
        """A name a person or discovery chose (comment, then saved name), or None."""
        return comment_for(self._comments(), mac, ip) or self.names.name(mac) or None

    def _best(self, mac: str | None, ip: str | None, hostname: str | None, vendor: str | None) -> str | None:
        return self.name(mac, ip) or hostname or (f"{vendor} device" if vendor else None)

    def label(self, dev) -> str:
        """What to call a Pi-hole device: never empty."""
        return self._best(dev.hwaddr, ipv4_of(dev), dev.name, dev.vendor) or dev.hwaddr

    def query_label(self, mac: str | None, ip: str, hostname: str | None) -> str:
        """What to call the sender of a query, which may have no MAC yet: never empty."""
        vendor = self._vendors.get(mac) if mac else None
        return self._best(mac, ip, hostname if hostname != ip else None, vendor) or ip

    def source(self, dev) -> str:
        """Where label(dev) came from, in words."""
        if comment_for(self._comments(), dev.hwaddr, ipv4_of(dev)):
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

    def find(self, query: str, devices: list[Device]) -> list[Found]:
        """The Devices with a MAC matching a MAC, an IP, or any name it goes by, whole or in part.

        Each comes with every MAC of it in `devices`, matched or not, newest lookup first. MACs are one
        device only when device_alias links them (ADR 0003): two devices both called "Apple device" stay two.
        """
        matched = self._matches(query, devices)
        by_device: dict[str, list[Device]] = {}
        for dev in sorted(devices, key=lambda d: -d.last_query):
            by_device.setdefault(self.device_of(dev.hwaddr), []).append(dev)
        wanted = {self.device_of(d.hwaddr) for d in matched}
        found = [Found(ident, tuple(macs), self._device_label(macs))
                 for ident, macs in by_device.items() if ident in wanted]
        return sorted(found, key=lambda f: -f.current.last_query)

    def _device_label(self, macs: list[Device]) -> str:
        """A chosen name (comment or saved) from any of its MACs, newest first; else the newest MAC's label."""
        chosen = next((dev for dev in macs if self.name(dev.hwaddr, ipv4_of(dev))), macs[0])
        return self.label(chosen)

    def _matches(self, query: str, devices: list[Device]) -> list[Device]:
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

    def _name_keys(self, dev) -> set[str]:
        saved = self.names.entries.get(dev.hwaddr) or {}
        names = (self.label(dev), self._comments().get(dev.hwaddr), saved.get("name"), dev.name)
        return {key for name in names if (key := name_key(name))}

