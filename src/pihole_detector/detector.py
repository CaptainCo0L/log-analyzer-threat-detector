"""Detector: turns queries and device snapshots into deduplicated, routed alerts."""

from __future__ import annotations

import logging
import time
from collections import Counter

from .baseline import Baseline
from .changes import PiholeChanges
from .config import Config, Settings
from .discovery import discover, nmap_options
from .domains import apex
from .intel import DomainSet, GravityIntel
from .directory import Directory
from .names import best_probe, ipv4_of, is_ipv4
from .namestore import NameStore
from .model import HIGH, Alert, Device, Query
from .rotation import format_sync, is_private, plan_sync
from .rules import Context, Seen
from .rules.devices import IotOffBaseline, new_devices, silent_devices
from .rules.intel_rules import DohBypass, ThreatIntelMatch
from .rules.randomness import DgaSingle, NxdomainBurst
from .rules.traffic import Beaconing, Tunneling
from .delivery import Delivery
from .alertlog import AlertLog
from .sinks import Telegram, build_digest
from .state import State

log = logging.getLogger(__name__)


class Detector:
    def __init__(self, cfg: Config, state: State, intel: GravityIntel, alert_log: AlertLog, telegram: Telegram,
                 names: NameStore | None = None, probe=discover, clients_api=None):
        self.cfg = cfg
        self.changes = PiholeChanges(cfg, clients_api)  # rotation sync; no API leaves Pi-hole alone
        self.directory = Directory(lambda: self.intel.names, names or NameStore(cfg.names_file))
        self.probe = probe
        self.state = state
        self.settings = Settings(cfg, state)  # first: the saved /set values apply before anything reads cfg
        self.intel = intel
        self.alert_log = alert_log
        self.telegram = telegram
        self.delivery = Delivery(cfg, state, telegram)
        self.ctx = Context(cfg=cfg, state=state, intel=intel, noisy=DomainSet(cfg.noisy_apexes),
                           baseline=Baseline(state, cfg))
        self.rules = [ThreatIntelMatch(), DohBypass(), DgaSingle(), NxdomainBurst(),
                      Tunneling(), Beaconing(), IotOffBaseline()]
        self.last_seen: dict[str, float] = {}  # MAC -> Pi-hole lastQuery, from the latest device snapshot
        self.labels: dict[str, str] = {}
        self.stats: Counter = Counter()
        self.digests = True
        self._last_prune = 0.0
        self._last_stats = 0.0

    # identity -----------------------------------------------------------------
    @property
    def names(self) -> NameStore:
        return self.directory.names

    @names.setter
    def names(self, store: NameStore) -> None:
        self.directory.names = store

    @property
    def clients_api(self):
        return self.changes.api

    @clients_api.setter
    def clients_api(self, api) -> None:
        self.changes.api = api

    @property
    def ip_to_mac(self) -> dict[str, str]:
        return self.directory.ip_to_mac

    def identify(self, q: Query) -> tuple[str, str, str]:
        """(ident, friendly label, address). Comment > discovered name > Pi-hole hostname > IP."""
        mac = self.ip_to_mac.get(q.client_ip)
        ident = mac or q.client_ip
        hostname = q.client_name if q.client_name and q.client_name != q.client_ip else None
        label = self.directory.name(mac, q.client_ip) or hostname or q.client_ip
        address = " · ".join(filter(None, [q.client_ip, mac]))
        self.labels[ident] = label
        return ident, label, address

    # inputs -------------------------------------------------------------------
    def learn(self, q: Query) -> tuple[str, str, str]:
        """Update baselines only. Used for every query, and alone for the --seed backfill."""
        ident, label, address = self.identify(q)
        self.state.touch_client(ident, q.time)
        if q.domain:
            self.state.remember_domain(ident, apex(q.domain), q.time)
        return ident, label, address

    def process_query(self, q: Query) -> list[Alert]:
        self.stats["queries"] += 1
        ident, label, address = self.learn(q)
        seen = Seen(ident=ident, label=label, apex=apex(q.domain) if q.domain else "", now=q.time,
                    address=address)
        alerts: list[Alert] = []
        for rule in self.rules:
            try:
                alerts.extend(rule.on_query(q, seen, self.ctx))
            except Exception:  # one broken rule must not blind the others
                log.exception("rule %s failed on %s", rule.name, q.domain)
        return self.emit(alerts)

    def process_devices(self, devices: list[Device], now: float) -> list[Alert]:
        self.last_seen = {dev.hwaddr: dev.last_query for dev in devices}
        self.directory.learn(devices)
        for dev in devices:
            if dev.is_real_mac:
                self.labels[dev.hwaddr] = self.directory.label(dev)
        first_run = not self.state.get("devices_seeded", False)
        alerts = new_devices(devices, self.ctx, now, quiet=first_run, rotated_from=self.rotated_from)
        self.state.put("devices_seeded", True)
        return self.emit(alerts)

    def rotated_from(self, dev: Device, now: float) -> tuple[str, str] | None:
        """(old MAC, name) if a new private MAC answers with a name another MAC already has.

        Nothing knows a just-seen MAC's name yet, so ask the device itself; it has just joined, so it is
        awake. The name is saved either way, so its later alerts carry it.
        """
        ip = ipv4_of(dev) if dev.is_private_mac else None
        if not ip:
            return None
        try:
            choice = best_probe(self.probe([ip], self.cfg.rotation_probe_wait).get(ip, {}))
        except Exception:  # an unanswered probe must not hide a new device
            log.exception("name probe for new device %s failed", dev.hwaddr)
            return None
        if not choice:
            return None
        self.names.update({dev.hwaddr: choice}, now)
        self.names.save()
        self.sync_rotation(dev.hwaddr, *choice, now)
        old = self.directory.previous_mac(dev.hwaddr, *choice)
        return (old, choice[0]) if old else None

    def tick(self, now: float) -> list[Alert]:
        """Periodic work: pruning windows, silent devices, the daily digest."""
        alerts: list[Alert] = []
        if now - self._last_prune >= 600:
            self._last_prune = now
            for rule in self.rules:
                rule.prune(now)
            self.state.prune(now)
            alerts = self.emit(silent_devices(self.ctx, now, self.labels))
        if now - self._last_stats >= 3600:
            self._last_stats = now
            # docker logs otherwise show only alerts; this proves polling is alive between them
            log.info("stats: %d queries, %d HIGH, %d MEDIUM, %d LOW since the last report",
                     self.stats["queries"], self.stats["alert_HIGH"], self.stats["alert_MEDIUM"],
                     self.stats["alert_LOW"])
        self.names.reload_if_changed()
        self.delivery.flush(now)
        if self.digests:
            self.maybe_discover(now)  # first, so the report below already carries fresh names
            self.maybe_digest(now)
        return alerts

    def maybe_discover(self, now: float) -> bool:
        """Once a week, at report time: ask the known devices for their names and save them."""
        local = time.localtime(now)
        today = time.strftime("%Y-%m-%d", local)
        if (local.tm_wday != self.cfg.discovery_weekday or local.tm_hour < self.cfg.digest_hour
                or self.state.get("last_discovery_day") == today):
            return False
        self.state.put("last_discovery_day", today)  # marked first: a failure must not retry every poll
        self.state.commit()
        try:
            self.discover_names(now)
        except Exception:  # the report must still go out, with the names already saved
            log.exception("weekly name discovery failed")
        return True

    def discover_names(self, now: float) -> None:
        ips = sorted(ip for ip in self.ip_to_mac if is_ipv4(ip))
        if not ips:
            return
        found = self.probe(ips, self.cfg.discovery_wait, **nmap_options(self.cfg))
        best = {}
        for ip, evidence in found.items():
            choice = best_probe(evidence)
            if choice and ip in self.ip_to_mac:
                best[self.ip_to_mac[ip]] = choice
        changes = self.names.update(best, now)
        self.names.save()
        for mac, (name, source) in best.items():
            if is_private(mac):  # one that was asleep when it joined is only found now
                self.sync_rotation(mac, name, source, now)
        for mac, old, new in changes:
            log.info("name for %s: %s -> %s", mac, old or "(none)", new)
        log.info("name discovery: %d device(s) answered of %d probed", len(best), len(ips))

    def sync_rotation(self, mac: str, name: str, source: str, now: float) -> None:
        """Move the device's Pi-hole Clients entry onto its new private MAC (see rotation.py). Every
        change is logged for clients-undo and sent to Telegram. A failure leaves the alert as it was."""
        if not (self.cfg.rotation_sync and self.clients_api):
            return
        try:
            plan = plan_sync(mac, name, source, self.clients_api.clients(), self.names.entries,
                             self.last_seen, self.cfg.rotation_keep)
        except Exception:
            log.exception("rotation sync for %s: reading Pi-hole Clients failed", mac)
            return
        if not plan.add:
            if plan.reason != "already a Pi-hole client":
                log.info("rotation sync for %s (%s): nothing done, %s", mac, name, plan.reason)
            return
        try:
            deleted, error = self.changes.apply_sync(plan, name, now)
        except Exception:
            log.exception("rotation sync for %s: adding it to Pi-hole Clients failed", mac)
            return
        if error:
            log.warning("rotation sync for %s: removing an old MAC failed: %s", mac, error)
        log.info("rotation sync: %s added %s, removed %s", name, mac, [e.mac for e in deleted] or "none")
        try:
            groups = self.clients_api.groups()
        except Exception:
            groups = {}
        undo = ([[self.delivery.button("↩️ Undo", {"kind": "undo_rotation", "time": now}, now)]]
                if self.cfg.bot_enabled else None)
        self.delivery.send(format_sync(name, plan.add, deleted, groups, error), undo)

    # outputs ------------------------------------------------------------------
    def emit(self, alerts: list[Alert]) -> list[Alert]:
        out = []
        for alert in alerts:
            hours = self.cfg.dedup_hours if alert.severity == HIGH else self.cfg.digest_dedup_hours
            if self.state.suppress(alert.dedup, alert.time, hours * 3600):
                continue
            out.append(alert)
            self.stats[f"alert_{alert.severity}"] += 1
            self.alert_log.write(alert)
            log.info("[%s] %s: %s", alert.severity, alert.rule, alert.message)
            self.delivery.route(alert)
        return out

    def maybe_digest(self, now: float, force: bool = False) -> bool:
        last = self.state.get("last_digest")
        local = time.localtime(now)
        today = time.strftime("%Y-%m-%d", local)
        if last is None and not force:
            # First run: open the window now; the first digest goes out at the next digest hour.
            self.state.put("last_digest", now)
            if local.tm_hour >= self.cfg.digest_hour:
                self.state.put("last_digest_day", today)
            return False
        due = local.tm_hour >= self.cfg.digest_hour and self.state.get("last_digest_day") != today
        if not (due or force):
            return False
        records = self.directory.relabel(self.alert_log.read(last or 0, now))
        text = build_digest(records, dict(self.stats), start=last or now, end=now)
        buttons = None
        if self.cfg.bot_enabled:
            days = max(1, round((now - (last or now)) / 86400))
            buttons = [[self.delivery.button("📄 Full report", {"kind": "full_report", "days": days, "end": now}, now)]]
        sent = self.delivery.send(text, buttons)
        # The digest doubles as the heartbeat, so leave a trace of it either way.
        log.info("digest %s: %d alert(s)", "sent" if sent else "NOT sent", len(records))
        self.state.put("last_digest", now)
        self.state.put("last_digest_day", today)
        self.stats.clear()
        self.state.commit()
        return True
