"""Two-way Telegram bot: the owner's commands and button presses, answered from the detector's state.

A background thread long-polls getUpdates and only queues what arrives. Every update is handled on
the main loop's thread (`drain`), so the SQLite state and the Pi-hole session are never shared.
Only the owner's private chat is answered: chat.id and from.id must both be TELEGRAM_CHAT_ID.
"""

from __future__ import annotations

import ipaddress
import logging
import queue
import re
import threading
import time
from collections import Counter

from .domains import apex
from .namestore import MAC, mac_from_address, relabel
from .report import build_report
from .rotation import is_private
from .sinks import RULES, SEVERITY_ICON, TELEGRAM_LIMIT, esc, when
from .model import HIGH, LOW, MEDIUM

log = logging.getLogger(__name__)

BOT_COMMANDS = [
    ("status", "Is Pi-hole up, and what has the detector seen"),
    ("report", "Alerts of the last N days: /report 7"),
    ("devices", "Who is online now (/devices all for everyone)"),
    ("whois", "One device: /whois <name, IP or MAC>"),
    ("help", "What I can do"),
]
WRITE_COMMANDS: set[str] = set()  # commands that change something; refused when older than STALE_SECONDS
STALE_SECONDS = 300
ONLINE_SECONDS = 900
MAX_REPORT_DAYS = 30


def ago(seconds: float) -> str:
    seconds = max(seconds, 0)
    if seconds < 90:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.0f} min"
    if seconds < 2 * 86400:
        return f"{seconds / 3600:.0f} h"
    return f"{seconds / 86400:.0f} d"


class TelegramPoller(threading.Thread):
    """Long-polls getUpdates and queues each update. Touches nothing else."""

    def __init__(self, telegram, inbox: queue.Queue, offset: int = 0, timeout: int = 25):
        super().__init__(name="telegram-poller", daemon=True)
        self.telegram, self.inbox, self.offset, self.timeout = telegram, inbox, offset, timeout
        self.stopping = threading.Event()

    def poll_once(self) -> int:
        updates = self.telegram.get_updates(self.offset, self.timeout)
        for update in updates:
            self.inbox.put(update)
            self.offset = max(self.offset, int(update.get("update_id", 0)) + 1)
        return len(updates)

    def run(self) -> None:
        while not self.stopping.is_set():
            started = time.monotonic()
            if not self.poll_once() and time.monotonic() - started < 1:
                self.stopping.wait(5)  # failed fast (network down): don't spin


def start_bot(det, api, run: bool = True):
    """(bot, inbox, poller) when BOT_ENABLED, else None. Clears any webhook (getUpdates is refused
    while one is set) and registers the "/" menu for the owner's chat."""
    if not (det.cfg.bot_enabled and det.telegram.configured):
        return None
    det.telegram.delete_webhook()
    det.telegram.set_commands(BOT_COMMANDS)
    inbox: queue.Queue = queue.Queue()
    poller = TelegramPoller(det.telegram, inbox, offset=int(det.state.get("bot_offset", 0)))
    if run:
        poller.start()
    return Bot(det, api, det.telegram), inbox, poller


def drain(inbox: queue.Queue, bot: "Bot", state, now: float) -> None:
    """Handle everything the poller queued; remember the offset so a restart doesn't replay it."""
    while True:
        try:
            update = inbox.get_nowait()
        except queue.Empty:
            return
        try:
            bot.handle(update, now)
        except Exception:
            log.exception("telegram update %s failed", update.get("update_id"))
        state.put("bot_offset", int(update.get("update_id", 0)) + 1)


class Bot:
    def __init__(self, det, api, telegram, started: float | None = None):
        self.det, self.api, self.telegram = det, api, telegram
        self.started = started if started is not None else time.time()
        self.owner = str(det.cfg.telegram_chat_id)
        self._strangers: set[str] = set()

    # dispatch -------------------------------------------------------------------------------
    def _is_owner(self, chat: dict, sender: dict) -> bool:
        ok = str(chat.get("id")) == self.owner and str(sender.get("id")) == self.owner
        if not ok:
            who = f"{chat.get('id')}/{sender.get('id')}"
            if who not in self._strangers:
                self._strangers.add(who)
                log.warning("telegram: ignoring a message from chat/user %s (not the owner)", who)
        return ok

    def handle(self, update: dict, now: float) -> None:
        if "callback_query" in update:
            cb = update["callback_query"]
            chat = (cb.get("message") or {}).get("chat") or {}
            if self._is_owner(chat, cb.get("from") or {}):
                self.on_press(cb, now)
            return
        msg = update.get("message")
        if not isinstance(msg, dict) or not self._is_owner(msg.get("chat") or {}, msg.get("from") or {}):
            return
        text = (msg.get("text") or "").strip()
        command, _, rest = text.partition(" ")
        command = command.split("@", 1)[0].lstrip("/").lower() if command.startswith("/") else ""
        args = rest.split()
        if command in WRITE_COMMANDS and now - float(msg.get("date") or 0) > STALE_SECONDS:
            self.reply("⌛ That command is from a while ago, so I didn't run it. Send it again if you still want it.")
            return
        handler = getattr(self, f"cmd_{command}", None) if command else None
        (handler or self.cmd_help)(args, now)

    def on_press(self, cb: dict, now: float) -> None:
        data = cb.get("data") or ""
        payload = self.det.state.take_action(data[2:], now) if data.startswith("a:") else None
        if payload is None:
            self.telegram.answer_callback(cb.get("id", ""), "This button has expired. Use a command instead, "
                                                           "e.g. /report or /status.")
            return
        handler = getattr(self, f"press_{payload.get('kind')}", None)
        if not handler:
            self.telegram.answer_callback(cb.get("id", ""), "Unknown button.")
            return
        self.telegram.answer_callback(cb.get("id", ""), handler(payload, now) or "")

    def reply(self, text: str, buttons=None) -> bool:
        return self.telegram.send(text, time.time(), capped=False, buttons=buttons)

    def button(self, label: str, payload: dict, now: float, style: str | None = None) -> dict:
        btn = {"text": label, "callback_data": f"a:{self.det.state.add_action(payload, now)}"}
        if style:
            btn["style"] = style
        return btn

    # /help ----------------------------------------------------------------------------------
    def cmd_help(self, args, now) -> None:
        lines = ["🤖 <b>Pi-hole detector</b>", ""] + [f"/{c} - {esc(d)}" for c, d in BOT_COMMANDS]
        self.reply("\n".join(lines))

    cmd_start = cmd_help

    # /status --------------------------------------------------------------------------------
    def cmd_status(self, args, now) -> None:
        cfg, stats = self.det.cfg, self.det.stats
        try:
            blocking = self.api.get("/dns/blocking")
            timer = f", back on in {ago(blocking['timer'])}" if blocking.get("timer") else ""
            pihole = f"✅ Pi-hole up, blocking {esc(blocking.get('blocking'))}{timer}"
        except Exception as exc:
            pihole = f"🚨 Pi-hole not reachable ({esc(type(exc).__name__)})"
        alerts = "   ".join(f"{SEVERITY_ICON[s]} {stats.get(f'alert_{s}', 0)} {s.lower()}" for s in (HIGH, MEDIUM, LOW))
        last = self.det.state.get("last_digest")
        local = time.localtime(now)
        next_report = time.mktime((local.tm_year, local.tm_mon, local.tm_mday + (local.tm_hour >= cfg.digest_hour),
                                   cfg.digest_hour, 0, 0, 0, 0, -1))
        lines = [
            "📟 <b>Status</b>", "",
            pihole,
            f"🛰 Detector up {ago(now - self.started)} · {stats.get('queries', 0):,} lookups checked "
            f"since {esc(when(last)) if last else 'start'}",
            alerts,
            f"🔔 Instant alerts {'on' if cfg.push_enabled else 'off'} · next report {esc(when(next_report))}",
            f"🔁 Rotation sync {'on' if cfg.rotation_sync else 'off'} · nmap {'on' if cfg.nmap_enabled else 'off'}",
        ]
        if stats.get("api_failures"):
            lines.append(f"⚠️ {stats['api_failures']} failed polls since the last report")
        self.reply("\n".join(lines))

    # /report --------------------------------------------------------------------------------
    def _records(self, days: float, now: float) -> list[dict]:
        start = now - days * 86400
        records = [r for r in self.det.jsonl.since(start) if r.get("time", 0) <= now]
        return relabel(records, lambda mac: self.det.display_name(mac))

    def cmd_report(self, args, now) -> None:
        try:
            days = min(max(int(args[0]), 1), MAX_REPORT_DAYS) if args else 7
        except ValueError:
            days = 7
        records = self._records(days, now)
        by_sev = Counter(r["severity"] for r in records)
        lines = [f"📊 <b>Last {days} days</b>", f"<i>{esc(when(now - days * 86400))} → {esc(when(now))}</i>", ""]
        if not records:
            lines.append("✨ No alerts.")
        else:
            lines.append("   ".join(f"{SEVERITY_ICON[s]} {by_sev[s]} {s.lower()}" for s in (HIGH, MEDIUM, LOW)))
            by_rule = Counter(r["rule"] for r in records)
            repeats = Counter((r.get("client", "?"), r["rule"], r.get("domain") or "") for r in records)
            detail = [f"<b>{esc(RULES.get(rule, (rule, ''))[0])}</b>: {count}" for rule, count in by_rule.most_common()]
            detail += ["", "<b>Most repeated</b>"]
            detail += [f"{n}× {esc(who)} · {esc(rule)}" + (f" · <code>{esc(dom)}</code>" if dom else "")
                       for (who, rule, dom), n in repeats.most_common(10)]
            body = "\n".join(detail)
            room = TELEGRAM_LIMIT - len("\n".join(lines)) - 80
            if len(body) > room:
                body = body[:room].rsplit("\n", 1)[0] + "\n…"
            lines += ["", f"<blockquote expandable>{body}</blockquote>"]
        full = self.button("📄 Full report", {"kind": "full_report", "days": days, "end": now}, now)
        self.reply("\n".join(lines), buttons=[[full]])

    def press_full_report(self, payload: dict, now: float) -> str:
        days, end = payload["days"], payload["end"]
        records = self._records(days, end)
        text = build_report(records, end - days * 86400, end, push_cap=self.det.cfg.push_cap_per_hour)
        name = f"pihole-report-{time.strftime('%Y-%m-%d', time.localtime(end))}-{days}d.md"
        self.telegram.send_document(name, text.encode("utf-8"), caption=f"Alerts of the last {days} days")
        return "Sending the full report"

    # /devices -------------------------------------------------------------------------------
    def _groups_by_mac(self) -> tuple[dict[str, tuple[int, ...]], dict[int, str]]:
        try:
            return {c.mac: c.groups for c in self.api.clients()}, self.api.groups()
        except Exception:
            log.exception("telegram: reading Pi-hole Clients failed")
            return {}, {}

    def _name(self, dev) -> str:
        ip = next((i for i in dev.ips if "." in i), None)
        return self.det.display_name(dev.hwaddr, ip) or dev.name or (f"{dev.vendor} device" if dev.vendor else dev.hwaddr)

    def cmd_devices(self, args, now) -> None:
        try:
            devices = [d for d in self.api.devices() if d.is_real_mac]
        except Exception as exc:
            self.reply(f"🚨 Couldn't ask Pi-hole for its devices ({esc(type(exc).__name__)}).")
            return
        groups, names = self._groups_by_mac()
        show_all = bool(args) and args[0].lower() == "all"
        devices.sort(key=lambda d: -d.last_query)
        online = [d for d in devices if now - d.last_query <= ONLINE_SECONDS]
        shown = devices if show_all else online
        lines = [f"📶 <b>{len(online)} online</b>" + (f" · {len(devices)} known" if show_all else ""), ""]
        for d in shown:
            ip = next((i for i in d.ips if "." in i), "-")
            member = ", ".join(names.get(g, str(g)) for g in groups.get(d.hwaddr, ())) or "no Clients entry"
            seen = "now" if now - d.last_query <= ONLINE_SECONDS else f"{ago(now - d.last_query)} ago"
            lines.append(f"• <b>{esc(self._name(d))}</b> - {esc(ip)} · {esc(member)} · {seen}")
        offline = len(devices) - len(online)
        if offline and not show_all:
            lines += ["", f"<i>{offline} offline (/devices all)</i>"]
        self.reply(_fit("\n".join(lines)))

    # /whois ---------------------------------------------------------------------------------
    def _find(self, query: str, devices) -> list:
        q = query.strip().lower()
        if MAC.fullmatch(q):
            return [d for d in devices if d.hwaddr == q]
        try:
            ipaddress.ip_address(q)
            return [d for d in devices if q in d.ips]
        except ValueError:
            pass
        key = name_key(query)
        if not key:
            return []
        known = {d.hwaddr: self._name_keys(d) for d in devices}
        exact = [d for d in devices if key in known[d.hwaddr]]
        return exact or [d for d in devices if any(key in name for name in known[d.hwaddr])]

    def _name_keys(self, dev) -> set[str]:
        """Every name a device goes by (display name, Clients comment, discovered name, Pi-hole hostname),
        reduced to letters and digits so "Aswins ipad" finds "Aswins-iPad"."""
        saved = self.det.names.entries.get(dev.hwaddr) or {}
        names = (self._name(dev), self.det.intel.names.get(dev.hwaddr), saved.get("name"), dev.name)
        return {key for name in names if (key := name_key(name))}

    def cmd_whois(self, args, now) -> None:
        if not args:
            self.reply("Usage: /whois <name, IP or MAC>, e.g. /whois Aswins-iPad")
            return
        try:
            devices = [d for d in self.api.devices() if d.is_real_mac]
        except Exception as exc:
            self.reply(f"🚨 Couldn't ask Pi-hole for its devices ({esc(type(exc).__name__)}).")
            return
        found = self._find(" ".join(args), devices)
        if not found:
            self.reply(f"No device matches <code>{esc(' '.join(args))}</code>. Try /devices all.")
            return
        found.sort(key=lambda d: -d.last_query)
        if len(found) > 1 and len({name_key(self._name(d)) for d in found}) == 1:
            # One device on several private MACs: show the one in use, mention the others.
            self.reply(self._whois(found[0], now, others=found[1:]))
            return
        if len(found) > 1:
            listed = "\n".join(f"• {esc(self._name(d))} - <code>{d.hwaddr}</code>" for d in found[:15])
            self.reply(f"Several devices match:\n{listed}\n\nAsk again with the MAC.")
            return
        self.reply(self._whois(found[0], now))

    def _whois(self, dev, now: float, others=()) -> str:
        mac = dev.hwaddr
        ip = next((i for i in dev.ips if "." in i), None)
        comment = self.det.intel.names.get(mac) or (self.det.intel.names.get(ip) if ip else None)
        saved = self.det.names.entries.get(mac)
        source = ("Clients comment" if comment else f"discovered ({saved['source']})" if saved
                  else "Pi-hole hostname" if dev.name else "vendor guess")
        groups, names = self._groups_by_mac()
        member = ", ".join(names.get(g, str(g)) for g in groups.get(mac, ())) or "no Clients entry"
        lines = [
            f"🔎 <b>{esc(self._name(dev))}</b>", "",
            f"MAC <code>{mac}</code> ({'private' if is_private(mac) else 'burned-in'}) · {esc(dev.vendor or 'unknown vendor')}",
            *(f"Also seen as <code>{o.hwaddr}</code>, last lookup "
              + (f"{ago(now - o.last_query)} ago" if o.last_query else "never") for o in others),
            f"IP {esc(', '.join(dev.ips) or 'none')}",
            f"Name from: {source}" + (f" · Pi-hole hostname {esc(dev.name)}" if dev.name and source != "Pi-hole hostname" else ""),
            f"Groups: {esc(member)}",
            f"First seen {esc(when(dev.first_seen))} · last lookup "
            + (f"{ago(now - dev.last_query)} ago" if dev.last_query else "never"),
        ]
        if ip:
            try:
                queries = self.api.queries_since(now - 86400, filters={"client_ip": ip})
                top = Counter(apex(q.domain) for q in queries if q.domain).most_common(10)
                lines += ["", f"<b>Top domains, last 24 h</b> ({len(queries):,} lookups)"]
                lines += [f"{i}. <code>{esc(d)}</code> - {n:,}" for i, (d, n) in enumerate(top, 1)] or ["none"]
            except Exception:
                log.exception("telegram: reading queries for %s failed", ip)
        recent = [r for r in self.det.jsonl.since(now - 30 * 86400) if mac_from_address(r.get("address")) == mac]
        recent.sort(key=lambda r: -r.get("time", 0))
        lines += ["", "<b>Recent alerts</b>"]
        lines += [f"{SEVERITY_ICON.get(r['severity'], '⚪')} {esc(when(r['time']))} · {esc(r['rule'])}"
                  + (f" · <code>{esc(r['domain'])}</code>" if r.get("domain") else "") for r in recent[:5]] or ["none in 30 days"]
        return _fit("\n".join(lines))


def name_key(text: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").casefold())


def _fit(text: str) -> str:
    if len(text) <= TELEGRAM_LIMIT:
        return text
    return text[: TELEGRAM_LIMIT - 20].rsplit("\n", 1)[0] + "\n<i>… cut short</i>"
