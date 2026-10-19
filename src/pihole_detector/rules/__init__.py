"""Detection rules.

Each query rule implements `on_query(q, seen, ctx) -> list[Alert]`, where `seen` describes this
query from the detector's point of view (client identity, apex, whether the apex is new for the
client). Windowed rules keep their own short-lived in-memory state and expose `prune(now)`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..config import Config
from ..intel import DomainSet, GravityIntel
from ..model import Alert, Query
from ..state import State

BLOCKED_STATUSES = {
    "GRAVITY", "REGEX", "DENYLIST", "EXTERNAL_BLOCKED_IP", "EXTERNAL_BLOCKED_NULL",
    "EXTERNAL_BLOCKED_NXRA", "GRAVITY_CNAME", "REGEX_CNAME", "DENYLIST_CNAME", "SPECIAL_DOMAIN",
}


@dataclass
class Context:
    cfg: Config
    state: State
    intel: GravityIntel
    noisy: DomainSet


@dataclass(frozen=True)
class Seen:
    ident: str          # MAC if known, else IP
    label: str          # human label for messages: "name (ip, mac)"
    apex: str
    new_apex: bool      # first time this client asked for this apex
    now: float


def block_hint(domain: str) -> str:
    return f"sudo docker exec pihole pihole deny {domain}"


def make_alert(
    severity: str, rule: str, seen: Seen, domain: str, message: str, evidence: dict, per_client: bool = False
) -> Alert:
    """Dedup is per (rule, client, apex), or per (rule, client) for burst rules spanning many apexes."""
    return Alert(
        time=seen.now,
        severity=severity,
        rule=rule,
        client=seen.label,
        domain=domain,
        message=message,
        evidence=evidence,
        dedup=f"{rule}|{seen.ident}" + ("" if per_client else f"|{seen.apex}"),
    )


class QueryRule:
    name = "base"

    def on_query(self, q: Query, seen: Seen, ctx: Context) -> list[Alert]:
        raise NotImplementedError

    def prune(self, now: float) -> None:
        pass
