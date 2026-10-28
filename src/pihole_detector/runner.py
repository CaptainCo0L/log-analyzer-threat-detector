"""The service loop of `run`, one poll at a time, so its health and backoff rules can be tested.

Each `poll(now)` refreshes intel and devices when due, feeds new queries to the detector, answers the
bot, and tells the caller how long to sleep. Pi-hole is the LAN's only DNS server, so FAIL_THRESHOLD
failed polls in a row push "Pi-hole API unreachable" (a LAN DNS outage), and the first good poll after
that pushes the recovery.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .bot import drain
from .sinks import format_down, format_up
from .source import ApiError, PiholeClient, Tail

log = logging.getLogger(__name__)
MAX_CATCHUP = 6 * 3600  # after downtime, resume at most this far back


class Runner:
    def __init__(self, det, api: PiholeClient, now: float, bot=None, heartbeat: Path | None = None):
        self.det, self.api, self.bot, self.heartbeat = det, api, bot, heartbeat
        self.tail = Tail(max(det.state.get("last_time", now - 60), now - MAX_CATCHUP))
        self.failures = 0
        self.down_since: float | None = None
        self.next_devices = self.next_intel = 0.0

    def poll(self, now: float) -> float:
        """One round of work; returns the seconds to wait before the next."""
        cfg, det = self.det.cfg, self.det
        if self.heartbeat:
            self.heartbeat.touch()  # the container healthcheck reads its age
        try:
            if now >= self.next_intel:
                det.intel.refresh()
                self.next_intel = now + cfg.intel_seconds
            if now >= self.next_devices:
                det.process_devices(self.api.devices(), now)
                self.next_devices = now + cfg.devices_seconds
            for q in self.tail.feed(self.api.queries_since(self.tail.since), now):
                det.process_query(q)
            det.state.put("last_time", self.tail.mark)
            if self.failures >= cfg.fail_threshold and cfg.health_push_enabled:
                det.delivery.send(format_up(now - self.down_since))
            self.failures, self.down_since = 0, None
        except ApiError as exc:
            self.failures += 1
            det.stats["api_failures"] += 1
            self.down_since = self.down_since or now
            log.warning("poll failed (%d in a row): %s", self.failures, exc)
            if self.failures == cfg.fail_threshold and cfg.health_push_enabled:
                det.delivery.send(format_down(self.failures, str(exc)))
        if self.bot:
            bot, inbox, _ = self.bot
            drain(inbox, bot, det.state, now)
        det.tick(now)
        det.state.commit()
        # Back off while failing (3, 6, 12, 24, 30 s...) instead of retrying a login every poll.
        return min(cfg.poll_seconds * 2 ** min(self.failures, 4), 30) if self.failures else cfg.poll_seconds
