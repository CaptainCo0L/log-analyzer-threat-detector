"""Threat-intel and group data read (read-only) from Pi-hole's gravity.db."""

from __future__ import annotations

import logging
import os
import sqlite3
from pathlib import Path

from .domains import normalise

log = logging.getLogger(__name__)


def parent_domains(domain: str):
    """`a.b.example.com` -> a.b.example.com, b.example.com, example.com, com."""
    labels = normalise(domain).split(".")
    for i in range(len(labels)):
        yield ".".join(labels[i:])


class DomainSet:
    """Wildcard domain set: an entry also matches all of its subdomains (HaGeZi 'wildcard' lists)."""

    def __init__(self, domains=()):
        self.domains = {normalise(d) for d in domains if d}

    def __len__(self) -> int:
        return len(self.domains)

    def match(self, domain: str) -> str | None:
        for candidate in parent_domains(domain):
            if candidate in self.domains:
                return candidate
        return None


def _connect_ro(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=5)


class GravityIntel:
    """Loads the threat-intel list and group membership, reloading when gravity.db is replaced.

    The directory (not the file) must be mounted: `pihole -g` swaps in a new gravity.db, and a
    single-file bind mount would keep showing the old inode forever.
    """

    def __init__(self, path: Path, list_match: str, iot_group: str,
                 extra_threats=(), extra_iot=()):
        self.path = Path(path)
        self.list_match = list_match
        self.iot_group = iot_group
        # Extras always apply on top of gravity.db (replay/tests, or local additions).
        self.extra_threats = [normalise(d) for d in extra_threats]
        self.extra_iot = {c.lower() for c in extra_iot}
        self.threats = DomainSet(self.extra_threats)
        self.iot_clients: set[str] = set(self.extra_iot)
        self.names: dict[str, str] = {}   # MAC/IP -> the comment on the Pi-hole Clients entry
        self.list_ids: list[int] = []
        self._stamp: tuple[int, float] | None = None

    def refresh(self) -> bool:
        """Reload if the file changed. Returns True when reloaded."""
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            log.warning("gravity db not found at %s; using only %d extra threat domains",
                        self.path, len(self.extra_threats))
            return False
        stamp = (st.st_ino, st.st_mtime)
        if stamp == self._stamp:
            return False
        with _connect_ro(self.path) as db:
            ids = [
                row[0]
                for row in db.execute(
                    "SELECT id FROM adlist WHERE enabled = 1 AND address LIKE ?",
                    (f"%{self.list_match}%",),
                )
            ]
            marks = ",".join("?" * len(ids))
            domains = (
                [row[0] for row in db.execute(f"SELECT domain FROM gravity WHERE adlist_id IN ({marks})", ids)]
                if ids
                else []
            )
            clients = db.execute(
                'SELECT c.ip FROM client c JOIN client_by_group cg ON cg.client_id = c.id '
                'JOIN "group" g ON g.id = cg.group_id WHERE g.name = ?',
                (self.iot_group,),
            ).fetchall()
            names = db.execute("SELECT ip, comment FROM client WHERE comment IS NOT NULL AND comment != ''").fetchall()
        self.names = {ip.lower(): comment.strip() for ip, comment in names}
        self.list_ids = ids
        self.threats = DomainSet(domains + self.extra_threats)
        self.iot_clients = {row[0].lower() for row in clients} | self.extra_iot
        self._stamp = stamp
        log.info(
            "intel loaded: %d threat domains from adlists %s, %d %s clients",
            len(self.threats), ids, len(self.iot_clients), self.iot_group,
        )
        return True


# Hostnames whose lookup means a device is about to resolve over DoH/DoT, bypassing Pi-hole.
# Entries also match their subdomains (e.g. chrome.cloudflare-dns.com).
DOH_RESOLVERS = DomainSet([
    "dns.google", "dns64.dns.google",
    "cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
    "dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
    "doh.opendns.com", "dns.opendns.com",
    "dns.nextdns.io",
    "dns.adguard-dns.com", "dns.adguard.com",
    "doh.dns.sb", "dns.mullvad.net", "doh.mullvad.net",
    "dns.controld.com", "freedns.controld.com",
])
