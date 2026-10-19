"""Detector: turns queries and device snapshots into deduplicated, routed alerts."""

from __future__ import annotations

import logging
import time
from collections import Counter

from .config import Config
from .domains import apex
from .intel import DomainSet, GravityIntel
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
    def __init__(self, cfg: Config, state: State, intel: GravityIntel, jsonl: JsonlSink, telegram: Telegram):
        self.cfg = cfg
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
    def identify(self, q: Query) -> tuple[str, str]:
        mac = self.ip_to_mac.get(q.client_ip)
        ident = mac or q.client_ip
        name = q.client_name if q.client_name and q.client_name != q.client_ip else None
        label = " ".join(filter(None, [name, f"({q.client_ip}{', ' + mac if mac else ''})"]))
        self.labels[ident] = label
        return ident, label

    # inputs -------------------------------------------------------------------
    def learn(self, q: Query) -> tuple[str, str, bool]:
        """Update baselines only. Used for every query, and alone for the --seed backfill."""
        ident, label = self.identify(q)
        self.state.touch_client(ident, q.time)
        site = apex(q.domain) if q.domain else ""
        new = self.state.remember_domain(ident, site, q.time) if site else False
        return ident, label, new

    def process_query(self, q: Query) -> list[Alert]:
        self.stats["queries"] += 1
        ident, label, new = self.learn(q)
        seen = Seen(ident=ident, label=label, apex=apex(q.domain) if q.domain else "", new_apex=new, now=q.time)
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
        if self.digests:
            self.maybe_digest(now)
        return alerts

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
        text = build_digest(self.jsonl.since(last or 0), dict(self.stats))
        self.telegram.send(text, now, capped=False)
        self.state.put("last_digest", now)
        self.state.put("last_digest_day", today)
        self.stats.clear()
        self.state.commit()
        return True
