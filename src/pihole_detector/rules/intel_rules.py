"""Rules that match queries against known lists: threat intel and DoH resolvers."""

from __future__ import annotations

from ..intel import DOH_RESOLVERS
from ..model import HIGH, MEDIUM, Query
from . import BLOCKED_STATUSES, Context, QueryRule, Seen, block_hint, make_alert


class ThreatIntelMatch(QueryRule):
    """Domain (or a parent, or a CNAME target) is on the threat-intel list - blocked or not."""

    name = "ti_match"

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        for name in filter(None, (q.domain, q.cname)):
            hit = ctx.intel.threats.match(name)
            if hit:
                blocked = q.status in BLOCKED_STATUSES
                return [make_alert(
                    HIGH, self.name, seen, q.domain,
                    f"{seen.label} looked up threat-intel domain {q.domain}"
                    + (" (blocked)" if blocked else " (NOT blocked - resolved normally)"),
                    {"matched": hit, "status": q.status, "reply": q.reply, "type": q.type,
                     "cname": q.cname, "block": None if blocked else block_hint(hit)},
                )]
        return []


class DohBypass(QueryRule):
    """Lookup of a public DoH/DoT resolver: the device is likely about to bypass Pi-hole."""

    name = "doh_bypass"

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        hit = DOH_RESOLVERS.match(q.domain)
        if not hit:
            return []
        return [make_alert(
            MEDIUM, self.name, seen, q.domain,
            f"{seen.label} resolved DoH/DoT resolver {q.domain}; its later lookups may bypass Pi-hole",
            {"matched": hit, "status": q.status, "block": block_hint(q.domain)},
        )]
