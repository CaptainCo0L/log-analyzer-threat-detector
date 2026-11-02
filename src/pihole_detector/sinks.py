"""The words of what the owner reads: pushes, the digest and health messages. Sends nothing."""

from __future__ import annotations

import html
import re
import time
from collections import Counter

from .model import HIGH, LOW, MEDIUM, Alert, join_address

TELEGRAM_LIMIT = 4000
SEVERITY_ICON = {HIGH: "🔴", MEDIUM: "🟠", LOW: "🟡"}

# rule -> (title, what it means / what to do)
RULES = {
    "ti_match": ("Malware / phishing domain",
                 "This domain is on a threat-intelligence list. Check which app or website on this device made the lookup."),
    "tunneling": ("Possible DNS tunneling",
                  "Lots of unusual lookups under one domain - a way to sneak data out through DNS. Worth checking the device."),
    "nxdomain_burst": ("Burst of random failed lookups",
                       "Many random names that don't exist - typical of malware searching for its control server."),
    "new_device": ("New device on the network",
                   "Not seen before. Could be a guest, a new gadget, or a phone that changed its private Wi-Fi address."),
    "dga_single": ("Random-looking domain",
                   "A machine-generated-looking name that actually resolved. Often harmless (CDNs, trackers), sometimes malware."),
    "beaconing": ("Regular check-ins",
                  "This device looks the domain up on a very steady timer, like software phoning home."),
    "iot_off_baseline": ("Smart device did something new",
                         "An IoT device contacted a domain it never used during its learning week."),
    "doh_bypass": ("Encrypted DNS in use",
                   "The device looked up a public encrypted-DNS server, so its later lookups may skip Pi-hole."),
    "device_silent": ("Device went quiet",
                      "No DNS lookups for a long time - switched off, away, or bypassing Pi-hole."),
}


def esc(value) -> str:
    return html.escape(str(value), quote=False)


def when(ts: float) -> str:
    return time.strftime("%a %d %b · %H:%M", time.localtime(ts))


def detail(alert: Alert) -> str:
    """One plain sentence with the rule-specific facts."""
    ev = alert.evidence or {}
    rule = alert.rule
    if rule == "ti_match":
        status = "Blocked by Pi-hole." if ev.get("block") is None else "⚠️ Not blocked - it resolved normally."
        via = f" (via CNAME {ev['cname']})" if ev.get("cname") else ""
        return f"{status}{via} List entry: {ev.get('matched')}"
    if rule == "tunneling":
        return "Seen in 10 min: " + "; ".join(ev.get("reasons", []))
    if rule == "nxdomain_burst":
        samples = ", ".join(ev.get("samples", [])[:3])
        return f"{ev.get('unique')} failed lookups in 5 min, e.g. {samples}"
    if rule == "new_device":
        was = f" · was {ev['previous_mac']}" if ev.get("previous_mac") else ""
        return f"Vendor: {ev.get('vendor') or 'unknown'} · IP: {', '.join(ev.get('ips') or []) or 'none'}{was}"
    if rule == "beaconing":
        return f"Every ~{ev.get('interval_s') or 0:.0f} s, {ev.get('hits')} times in a row"
    if rule == "device_silent":
        return f"Silent for {ev.get('hours')} h"
    if rule == "iot_off_baseline":
        return f"New domain for this device: {ev.get('apex')}"
    return ""


def format_push(alert: Alert, hint: bool = True) -> str:
    """The pushed alert. `hint=False` drops the "run on the NAS" block command, for when buttons carry it."""
    title, meaning = RULES.get(alert.rule, (alert.rule, ""))
    lines = [f"{SEVERITY_ICON.get(alert.severity, '⚪')} <b>{esc(title)}</b>", ""]
    device = f"📱 <b>{esc(alert.label)}</b>"
    extra = [part for part in (*alert.ips, alert.mac) if part and part != alert.label]
    if extra:
        device += f"  <i>{esc(' · '.join(extra))}</i>"
    lines.append(device)
    if alert.domain:
        lines.append(f"🌐 <code>{esc(alert.domain)}</code>")
    facts = detail(alert)
    if facts:
        lines += ["", esc(facts)]
    if meaning:
        lines += ["", f"💡 {esc(meaning)}"]
    block = (alert.evidence or {}).get("block")
    if block and hint:
        lines += ["", "🛡 To block it, run on the NAS:", f"<code>{esc(block)}</code>"]
    lines += ["", f"<i>{esc(when(alert.time))} · {esc(alert.severity)} · {esc(alert.rule)}</i>"]
    return "\n".join(lines)


def _digest_item(r: dict) -> str:
    who = esc(r.get("label", "?"))
    rule = r["rule"]
    ev = r.get("evidence") or {}
    if rule == "device_silent":
        return f"• {who} - silent {ev.get('hours', '?')} h"
    if rule == "new_device":
        return f"• {who} <i>{esc(join_address(r.get('ips'), r.get('mac')))}</i>"
    if rule == "beaconing":
        return f"• {who} → <code>{esc(r.get('domain'))}</code> every ~{ev.get('interval_s') or 0:.0f} s"
    if rule == "nxdomain_burst":
        return f"• {who} - {ev.get('unique')} random failed lookups"
    return f"• {who} → <code>{esc(r.get('domain'))}</code>"


def build_digest(records: list[dict], stats: dict, start: float | None = None, end: float | None = None) -> str:
    """One daily message. Always sent, even when empty: a missing digest means the detector died."""
    end = end or time.time()
    by_sev = Counter(r["severity"] for r in records)
    lines = ["📊 <b>Pi-hole daily report</b>"]
    if start:
        lines.append(f"<i>{esc(when(start))} → {esc(when(end))}</i>")
    lines.append("")
    failures = stats.get("api_failures", 0)
    health = "✅ Detector running" if not failures else f"⚠️ Detector running, {failures} failed polls"
    count = stats.get("queries", 0)
    lines.append(f"{health} · {count:,} lookup{'' if count == 1 else 's'} checked")
    if not records:
        lines.append("✨ Nothing suspicious.")
    else:
        lines.append("   ".join(f"{SEVERITY_ICON[s]} {by_sev[s]} {s.lower()}" for s in (HIGH, MEDIUM, LOW) if by_sev[s]))
        order = {HIGH: 0, MEDIUM: 1, LOW: 2}
        groups: dict[str, list[dict]] = {}
        for r in sorted(records, key=lambda r: (order.get(r["severity"], 3), r["time"])):
            groups.setdefault(r["rule"], []).append(r)
        for rule, items in groups.items():
            title = RULES.get(rule, (rule, ""))[0]
            lines += ["", f"{SEVERITY_ICON.get(items[0]['severity'], '⚪')} <b>{esc(title)}</b> ({len(items)})"]
            lines += [_digest_item(r) for r in items[:5]]
            if len(items) > 5:
                lines.append(f"  <i>+{len(items) - 5} more</i>")
    lines += ["", "<i>Full details: data/alerts.jsonl on the NAS</i>"]
    text = "\n".join(lines)
    if len(text) > TELEGRAM_LIMIT:
        text = text[: TELEGRAM_LIMIT - 60].rsplit("\n", 1)[0] + "\n<i>… cut short, see alerts.jsonl</i>"
    return text


def format_down(failures: int, reason: str) -> str:
    return ("🚨 <b>Pi-hole is not responding</b>\n\n"
            f"The detector couldn't reach it {failures} times in a row.\n"
            "Pi-hole is the only DNS server on your network, so if it is really down, "
            "no device can open websites.\n\n"
            f"<i>Reason: {esc(reason)}</i>")


def format_up(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    took = f"{minutes} min {secs} s" if minutes else f"{secs} s"
    return f"✅ <b>Pi-hole is back</b>\n\nReachable again after {took}."


def format_test(push_enabled: bool) -> str:
    mode = ("ON - HIGH alerts arrive instantly" if push_enabled
            else "OFF (trial mode) - everything goes into the 09:00 report")
    return f"👋 <b>Pi-hole detector connected</b>\n\nInstant alerts: {mode}."


def fit(text: str) -> str:
    """Cut a message down to one Telegram message, at a line break."""
    if len(text) <= TELEGRAM_LIMIT:
        return text
    return text[: TELEGRAM_LIMIT - 20].rsplit("\n", 1)[0] + "\n<i>… cut short</i>"


def strip_html(text: str) -> str:
    return html.unescape(re.sub(r"<[^>]+>", "", text))
