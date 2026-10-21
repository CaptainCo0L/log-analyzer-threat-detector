"""DGA-style rules: single random-looking domains and bursts of random NXDOMAIN lookups."""

from __future__ import annotations

from collections import defaultdict, deque

from ..domains import looks_random, registrable_label
from ..baseline import KNOWN
from ..model import HIGH, MEDIUM, Query
from . import BLOCKED_STATUSES, Context, QueryRule, Seen, make_alert


def _candidate(q: Query, ctx: Context) -> bool:
    # Single-label names are skipped: Chrome probes three random single-label names at startup
    # to detect NXDOMAIN-hijacking resolvers, which would otherwise look exactly like DGA.
    return "." in q.domain and not ctx.noisy.match(q.domain) and not q.domain.endswith(".arpa")


ANSWERED = {"IP", "CNAME", "DOMAIN", "RRNAME"}


class DgaSingle(QueryRule):
    """A random-looking name that *resolved*. NXDOMAIN ones are left to NxdomainBurst: a DGA
    burst would otherwise also raise one alert per name, and the one that resolves is the C2.

    Requires a positive answer, not merely "not NXDOMAIN": FTL leaves a client's retransmitted
    duplicate at reply UNKNOWN forever, so UNKNOWN carries no information either way. Blocked
    queries are skipped too: NULL blocking answers 0.0.0.0, which FTL reports as reply IP.

    Still fires while a client is learning (a cold start must not hide a DGA), but not for apexes
    the client has used for longer than the learning period or that many clients share. Live,
    those were carrier Wi-Fi calling (3gppnetwork.org) and an app SDK, re-alerting all day.
    """

    name = "dga_single"

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        if q.reply not in ANSWERED or q.status in BLOCKED_STATUSES or not _candidate(q, ctx):
            return []
        label = registrable_label(q.domain)
        if not looks_random(label):
            return []
        fam = ctx.baseline.familiarity(seen.ident, seen.apex, seen.now)
        if fam.shared or fam.stage == KNOWN:
            return []
        return [make_alert(
            MEDIUM, self.name, seen, q.domain,
            f"{seen.label} resolved random-looking domain {q.domain}",
            {"label": label, "reply": q.reply, "status": q.status},
        )]


class NxdomainBurst(QueryRule):
    """Many distinct random-looking names answered NXDOMAIN for one client in a short window."""

    name = "nxdomain_burst"

    def __init__(self):
        self.windows: dict[str, deque] = defaultdict(deque)

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        if q.reply != "NXDOMAIN" or not _candidate(q, ctx):
            return []
        if not looks_random(registrable_label(q.domain), min_len=8):
            return []
        window = self.windows[seen.ident]
        window.append((seen.now, q.domain))
        cutoff = seen.now - ctx.cfg.nxdomain_window
        while window and window[0][0] < cutoff:
            window.popleft()
        unique = {d for _, d in window}
        if len(unique) < ctx.cfg.nxdomain_threshold:
            return []
        return [make_alert(
            HIGH, self.name, seen, q.domain,
            f"{seen.label} got NXDOMAIN for {len(unique)} random-looking names in "
            f"{int(ctx.cfg.nxdomain_window // 60)} min (possible DGA malware hunting for its C2)",
            {"unique": len(unique), "samples": sorted(unique)[:10]},
            per_client=True,
        )]

    def prune(self, now: float) -> None:
        for key in [k for k, w in self.windows.items() if not w or w[-1][0] < now - 3600]:
            del self.windows[key]
