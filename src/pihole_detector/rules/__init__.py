"""Detection rules.

Each query rule implements `on_query(q, seen, ctx) -> list[Alert]`, where `seen` describes this
query from the detector's point of view (client identity, apex, whether the apex is new for the
client). Windowed rules keep their own short-lived in-memory state and expose `prune(now)`.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..baseline import Baseline
from ..config import Config
from ..domains import apex
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
    baseline: Baseline


@dataclass(frozen=True)
class Seen:
    ident: str          # the device, the same across its MACs (state.device_of); else the IP
    label: str          # friendly name (Pi-hole client comment / hostname), else the IP
    apex: str
    now: float
    ip: str = ""
    mac: str = ""       # the MAC this query came from, when known

    @property
    def origin(self) -> str:
        """The sender as Pi-hole's groups list it: the MAC in use, else the IP."""
        return self.mac or self.ip


def block_hint(domain: str) -> str:
    """The NAS command that blocks the domain's apex and every subdomain (`pihole deny` is exact only)."""
    return f"sudo docker exec pihole pihole --wild {apex(domain)}"


def make_alert(
    severity: str, rule: str, seen: Seen, domain: str, message: str, evidence: dict, per_device: bool = False
) -> Alert:
    """Dedup is per (rule, device, apex), or per (rule, device) for burst rules spanning many apexes."""
    return Alert(
        time=seen.now,
        severity=severity,
        rule=rule,
        label=seen.label,
        domain=domain,
        message=message,
        evidence=evidence,
        dedup=f"{rule}|{seen.ident}" + ("" if per_device else f"|{seen.apex}"),
        device=seen.ident,
        mac=seen.mac,
        ips=(seen.ip,),
    )


class QueryRule:
    name = "base"

    def on_query(self, q: Query, seen: Seen, ctx: Context) -> list[Alert]:
        raise NotImplementedError

    def prune(self, now: float) -> None:
        pass
