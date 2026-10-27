"""Per-device behaviour rules: IoT off-baseline lookups, new devices, silent devices."""

from __future__ import annotations

from ..baseline import NEW
from ..model import HIGH, LOW, MEDIUM, Alert, Device, Query
from . import BLOCKED_STATUSES, Context, QueryRule, Seen, block_hint, make_alert


class IotOffBaseline(QueryRule):
    """An IoT-group device asks for an apex it never used during its learning period.

    Shared apexes still count: a camera reaching a site the PCs use is still off its baseline.
    Blocked lookups don't: Pi-hole already stopped them.
    """

    name = "iot_off_baseline"

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        if (seen.ident not in ctx.intel.iot_clients or q.status in BLOCKED_STATUSES
                or ctx.noisy.match(q.domain)):
            return []
        if ctx.baseline.familiarity(seen.ident, seen.apex, seen.now).stage != NEW:
            return []
        return [make_alert(
            MEDIUM, self.name, seen, q.domain,
            f"IoT device {seen.label} queried {seen.apex} for the first time (outside its baseline)",
            {"apex": seen.apex, "status": q.status, "reply": q.reply, "block": block_hint(seen.apex)},
        )]


def new_devices(devices: list[Device], ctx: Context, now: float, quiet: bool,
                rotated_from=lambda dev, now: None) -> list[Alert]:
    """Alert on MACs never seen before. `quiet` records them without alerting (first run).

    `rotated_from(dev, now)` returns (old MAC, name) when the newcomer is a known device back on a new
    private MAC; that is LOW (digest), since phones and tablets do it on their own every so often.
    """
    alerts = []
    for dev in devices:
        if not dev.is_real_mac or ctx.state.known_device(dev.hwaddr):
            continue
        ctx.state.add_device(dev.hwaddr, now)
        if quiet:
            continue
        rotation = rotated_from(dev, now)
        if rotation:
            old_mac, name = rotation
            alerts.append(Alert(
                time=now, severity=LOW, rule="new_device", client=name, domain="",
                address=" · ".join(list(dev.ips[:2]) + [dev.hwaddr]),
                message=f"{name} rejoined on a new private Wi-Fi MAC {dev.hwaddr} (was {old_mac})",
                evidence={"hwaddr": dev.hwaddr, "vendor": dev.vendor, "ips": list(dev.ips),
                          "first_seen": dev.first_seen, "previous_mac": old_mac},
                dedup=f"new_device|{dev.hwaddr}",
            ))
            continue
        label = dev.name or dev.vendor or (dev.ips[0] if dev.ips else dev.hwaddr)
        alerts.append(Alert(
            time=now, severity=HIGH, rule="new_device", client=label, domain="",
            address=" · ".join(list(dev.ips[:2]) + [dev.hwaddr]),
            message=f"New device on the LAN: {dev.hwaddr} {dev.vendor or 'unknown vendor'}, "
                    f"IPs {', '.join(dev.ips) or 'none'} (may be a rotated private Wi-Fi MAC)",
            evidence={"hwaddr": dev.hwaddr, "vendor": dev.vendor, "ips": list(dev.ips),
                      "first_seen": dev.first_seen},
            dedup=f"new_device|{dev.hwaddr}",
        ))
    return alerts


def silent_devices(ctx: Context, now: float, labels: dict[str, str]) -> list[Alert]:
    cfg = ctx.cfg
    alerts = []
    for ident, last_seen in ctx.state.silent_clients(now - cfg.silent_hours * 3600, cfg.silent_min_queries):
        ctx.state.mark_silent(ident)
        hours = (now - last_seen) / 3600
        alerts.append(Alert(
            time=now, severity=LOW, rule="device_silent", client=labels.get(ident, ident), domain="",
            message=f"{labels.get(ident, ident)} has sent no DNS to Pi-hole for {hours:.0f} h "
                    "(offline, or bypassing Pi-hole)",
            evidence={"last_seen": last_seen, "hours": round(hours)},
            dedup=f"device_silent|{ident}",
            address=ident,
        ))
    return alerts
