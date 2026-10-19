"""Detector: turns queries and device snapshots into deduplicated, routed alerts."""

from __future__ import annotations

import logging
import time
from collections import Counter

from .config import Config
from .discovery import discover
from .domains import apex
from .intel import DomainSet, GravityIntel
from .namestore import NameStore, best_probe, relabel
from .model import HIGH, Alert, Device, Query
from .rules import Context, Seen
from .rules.devices import IotOffBaseline, new_devices, silent_devices
from .rules.intel_rules import DohBypass, ThreatIntelMatch
from .rules.randomness import DgaSingle, NxdomainBurst
from .rules.traffic import Beaconing, Tunneling
from .sinks import JsonlSink, Telegram, build_digest, format_push
from .state import State

log = logging.getLogger(__name__)


class Detector:
    def __init__(self, cfg: Config, state: State, intel: GravityIntel, jsonl: JsonlSink, telegram: Telegram,
                 names: NameStore | None = None, probe=discover):
        self.cfg = cfg
        self.names = names or NameStore(cfg.names_file)
        self.probe = probe
        self.state = state
        self.intel = intel
        self.jsonl = jsonl
        self.telegram = telegram
        self.ctx = Context(cfg=cfg, state=state, intel=intel, noisy=DomainSet(cfg.noisy_apexes))
        self.rules = [ThreatIntelMatch(), DohBypass(), DgaSingle(), NxdomainBurst(),
                      Tunneling(), Beaconing(), IotOffBaseline()]
        self.ip_to_mac: dict[str, str] = {}
        self.labels: dict[str, str] = {}
        self.stats: Counter = Counter()
        self.digests = True
        self._last_prune = 0.0

    # identity -----------------------------------------------------------------
    def display_name(self, mac: str | None, ip: str | None = None) -> str | None:
        """A human-chosen name wins: the Pi-hole Clients comment, then a name discovery found."""
        comments = self.intel.names
        return (mac and comments.get(mac)) or (ip and comments.get(ip)) or self.names.name(mac) or None

    def identify(self, q: Query) -> tuple[str, str, str]:
        """(ident, friendly label, address). Comment > discovered name > Pi-hole hostname > IP."""
        mac = self.ip_to_mac.get(q.client_ip)
        ident = mac or q.client_ip
        hostname = q.client_name if q.client_name and q.client_name != q.client_ip else None
        label = self.display_name(mac or q.client_ip, q.client_ip) or hostname or q.client_ip
        address = " · ".join(filter(None, [q.client_ip, mac]))
        self.labels[ident] = label
        return ident, label, address

    # inputs -------------------------------------------------------------------
    def learn(self, q: Query) -> tuple[str, str, str, bool]:
        """Update baselines only. Used for every query, and alone for the --seed backfill."""
        ident, label, address = self.identify(q)
        self.state.touch_client(ident, q.time)
        site = apex(q.domain) if q.domain else ""
        new = self.state.remember_domain(ident, site, q.time) if site else False
        return ident, label, address, new

    def process_query(self, q: Query) -> list[Alert]:
        self.stats["queries"] += 1
        ident, label, address, new = self.learn(q)
        seen = Seen(ident=ident, label=label, apex=apex(q.domain) if q.domain else "", new_apex=new,
                    now=q.time, address=address)
        alerts: list[Alert] = []
        for rule in self.rules:
            try:
                alerts.extend(rule.on_query(q, seen, self.ctx))
            except Exception:  # one broken rule must not blind the others
                log.exception("rule %s failed on %s", rule.name, q.domain)
        return self.emit(alerts)

    def process_devices(self, devices: list[Device], now: float) -> list[Alert]:
        for dev in devices:
            if dev.is_real_mac:
                for ip in dev.ips:
                    self.ip_to_mac[ip] = dev.hwaddr
                self.labels[dev.hwaddr] = self.display_name(dev.hwaddr) or self.labels.get(dev.hwaddr) or dev.name or dev.hwaddr
        first_run = not self.state.get("devices_seeded", False)
        alerts = new_devices(devices, self.ctx, now, quiet=first_run)
        self.state.put("devices_seeded", True)
        return self.emit(alerts)

    def tick(self, now: float) -> list[Alert]:
        """Periodic work: pruning windows, silent devices, the daily digest."""
        alerts: list[Alert] = []
        if now - self._last_prune >= 600:
            self._last_prune = now
            for rule in self.rules:
                rule.prune(now)
            self.state.prune(now)
            alerts = self.emit(silent_devices(self.ctx, now, self.labels))
        self.names.reload_if_changed()
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
        ips = sorted(ip for ip in self.ip_to_mac if "." in ip)  # IPv4 only
        if not ips:
            return
        found = self.probe(ips, self.cfg.discovery_wait)
        best = {}
        for ip, evidence in found.items():
            choice = best_probe(evidence)
            if choice and ip in self.ip_to_mac:
                best[self.ip_to_mac[ip]] = choice
        changes = self.names.update(best, now)
        self.names.save()
        for mac, old, new in changes:
            log.info("name for %s: %s -> %s", mac, old or "(none)", new)
        log.info("name discovery: %d device(s) answered of %d probed", len(best), len(ips))

    # outputs ------------------------------------------------------------------
    def emit(self, alerts: list[Alert]) -> list[Alert]:
        out = []
        for alert in alerts:
            if self.state.suppress(alert.dedup, alert.time, self.cfg.dedup_hours * 3600):
                continue
            out.append(alert)
            self.stats[f"alert_{alert.severity}"] += 1
            self.jsonl.write(alert)
            log.info("[%s] %s: %s", alert.severity, alert.rule, alert.message)
            if alert.severity == HIGH and self.cfg.push_enabled:
                self.telegram.send(format_push(alert), alert.time)
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
        records = relabel(self.jsonl.since(last or 0), lambda mac: self.display_name(mac))
        text = build_digest(records, dict(self.stats), start=last or now, end=now)
        self.telegram.send(text, now, capped=False)
        self.state.put("last_digest", now)
        self.state.put("last_digest_day", today)
        self.stats.clear()
        self.state.commit()
        return True
