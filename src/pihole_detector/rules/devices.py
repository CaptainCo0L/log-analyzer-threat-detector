"""Per-device behaviour rules: IoT off-baseline lookups, new devices, silent devices."""

from __future__ import annotations

from ..model import HIGH, LOW, MEDIUM, Alert, Device, Query
from . import Context, QueryRule, Seen, block_hint, make_alert


class IotOffBaseline(QueryRule):
    """An IoT-group device asks for an apex it never used during its learning period."""

    name = "iot_off_baseline"

    def on_query(self, q: Query, seen: Seen, ctx: Context):
        if not seen.new_apex or seen.ident not in ctx.intel.iot_clients or ctx.noisy.match(q.domain):
            return []
        first = ctx.state.client_first_seen(seen.ident)
        if first is None or seen.now - first < ctx.cfg.learning_days * 86400:
            return []  # still learning
        return [make_alert(
            MEDIUM, self.name, seen, q.domain,
            f"IoT device {seen.label} queried {seen.apex} for the first time (outside its baseline)",
            {"apex": seen.apex, "status": q.status, "reply": q.reply, "block": block_hint(seen.apex)},
        )]


def new_devices(devices: list[Device], ctx: Context, now: float, quiet: bool) -> list[Alert]:
    """Alert on MACs never seen before. `quiet` records them without alerting (first run)."""
    alerts = []
    for dev in devices:
        if not dev.is_real_mac or ctx.state.known_device(dev.hwaddr):
            continue
        ctx.state.add_device(dev.hwaddr, now)
        if quiet:
            continue
        label = dev.name or (dev.ips[0] if dev.ips else dev.hwaddr)
        alerts.append(Alert(
            time=now, severity=HIGH, rule="new_device", client=f"{label} ({dev.hwaddr})", domain="",
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
            evidence={"last_seen": last_seen},
            dedup=f"device_silent|{ident}",
        ))
    return alerts
