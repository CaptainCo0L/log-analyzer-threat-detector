"""Volume/timing rules: DNS tunneling and beaconing."""

from __future__ import annotations

import statistics
from collections import defaultdict, deque

from ..domains import subdomain_part
from ..model import HIGH, MEDIUM, Query
from . import BLOCKED_STATUSES, Context, QueryRule, Seen, make_alert

TUNNEL_TYPES = {"TXT", "NULL", "ANY"}


class _Window:
    __slots__ = ("events", "subs", "long", "txt")

    def __init__(self):
        self.events: deque = deque()          # (time, subdomain, is_long, is_txt)
        self.subs: dict[str, int] = defaultdict(int)
        self.long = 0
        self.txt = 0

    def add(self, event) -> None:
        self.events.append(event)
        _, sub, is_long, is_txt = event
        self.subs[sub] += 1
        self.long += is_long
        self.txt += is_txt

    def expire(self, cutoff: float) -> None:
        while self.events and self.events[0][0] < cutoff:
            _, sub, is_long, is_txt = self.events.popleft()
            self.subs[sub] -= 1
            if not self.subs[sub]:
                del self.subs[sub]
            self.long -= is_long
            self.txt -= is_txt


class Tunneling(QueryRule):
    """Data smuggled in query names: many unique subdomains, very long labels or heavy TXT under one apex."""

    name = "tunneling"

    def __init__(self):
        self.windows: dict[tuple[str, str], _Window] = defaultdict(_Window)

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        if ctx.noisy.match(q.domain):
            return []
        cfg = ctx.cfg
        sub = subdomain_part(q.domain)
        is_long = any(len(label) > cfg.tunnel_long_label for label in sub.split(".")) if sub else False
        window = self.windows[(seen.ident, seen.apex)]
        window.add((seen.now, sub, int(is_long), int(q.type in TUNNEL_TYPES)))
        window.expire(seen.now - cfg.tunnel_window)
        reasons = []
        if len(window.subs) >= cfg.tunnel_unique_subdomains:
            reasons.append(f"{len(window.subs)} unique subdomains")
        if window.long >= cfg.tunnel_long_label_count:
            reasons.append(f"{window.long} labels over {cfg.tunnel_long_label} chars")
        if window.txt >= cfg.tunnel_txt_count:
            reasons.append(f"{window.txt} TXT/NULL/ANY queries")
        if not reasons:
            return []
        return [make_alert(
            HIGH, self.name, seen, seen.apex,
            f"{seen.label} -> {seen.apex}: {', '.join(reasons)} in {int(cfg.tunnel_window // 60)} min "
            "(possible DNS tunneling / exfiltration)",
            {"reasons": reasons, "samples": sorted(window.subs)[:5]},
        )]

    def prune(self, now: float) -> None:
        for key in [k for k, w in self.windows.items() if not w.events or w.events[-1][0] < now - 3600]:
            del self.windows[key]


class Beaconing(QueryRule):
    """The same client resolves the same name at a near-constant interval (malware check-ins).

    Skipped, because they are periodic too and would otherwise dominate: blocked queries
    (ad/telemetry retries), names many clients use (OS connectivity checks), and apexes the
    client has used for longer than the learning period (IoT heartbeats to their vendor cloud).
    """

    name = "beaconing"
    collapse_seconds = 2.0  # A + AAAA (and retries) for one lookup arrive together
    max_prevalence = 2      # skip apexes in more than this many clients' baselines

    def __init__(self):
        self.times: dict[tuple[str, str], deque] = {}

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        cfg = ctx.cfg
        if q.status in BLOCKED_STATUSES or ctx.noisy.match(q.domain):
            return []
        key = (seen.ident, q.domain)
        times = self.times.get(key)
        if times is None:
            times = self.times[key] = deque(maxlen=cfg.beacon_min_hits + 1)
        if times and seen.now - times[-1] < self.collapse_seconds:
            return []
        times.append(seen.now)
        if len(times) <= cfg.beacon_min_hits:
            return []
        gaps = [b - a for a, b in zip(times, list(times)[1:])]
        mean = statistics.fmean(gaps)
        if not cfg.beacon_min_interval <= mean <= cfg.beacon_max_interval:
            return []
        cv = statistics.pstdev(gaps) / mean
        if cv > cfg.beacon_max_cv:
            return []
        if ctx.state.apex_prevalence(seen.apex) > self.max_prevalence:
            return []
        first = ctx.state.domain_first_seen(seen.ident, seen.apex)
        if first is not None and seen.now - first >= cfg.learning_days * 86400:
            return []
        return [make_alert(
            MEDIUM, self.name, seen, q.domain,
            f"{seen.label} resolves {q.domain} every ~{mean:.0f}s (jitter {cv:.2f}) - possible beaconing",
            {"interval_s": round(mean, 1), "cv": round(cv, 3), "hits": len(times)},
        )]

    def prune(self, now: float) -> None:
        stale = now - 2 * 3600
        for key in [k for k, t in self.times.items() if t[-1] < stale]:
            del self.times[key]
