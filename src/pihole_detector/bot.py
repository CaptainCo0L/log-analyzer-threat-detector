"""Two-way Telegram bot: the owner's commands and button presses, answered from the detector's state.

A background thread long-polls getUpdates and only queues what arrives. Every update is handled on
the main loop's thread (`drain`), so the SQLite state and the Pi-hole session are never shared.
Only the owner's private chat is answered: chat.id and from.id must both be TELEGRAM_CHAT_ID.
"""

from __future__ import annotations

import ipaddress
import json
import os
import logging
import queue
import re
import threading
import time
from collections import Counter
from pathlib import Path

from . import clientlog
from .config import SETTABLE, Config, parse_setting
from .domains import apex
from .namestore import MAC, mac_from_address, relabel
from .report import build_report
from .rotation import Client, is_private
from .sinks import RULES, SEVERITY_ICON, TELEGRAM_LIMIT, esc, when
from .model import HIGH, LOW, MEDIUM

log = logging.getLogger(__name__)

BOT_COMMANDS = [
    ("status", "Is Pi-hole up, and what has the detector seen"),
    ("report", "Alerts of the last N days: /report 7"),
    ("devices", "Who is online now (/devices all for everyone)"),
    ("whois", "One device: /whois <name, IP or MAC>"),
    ("block", "Block a domain and its subdomains: /block ads.example (or /block exact ...)"),
    ("unblock", "Remove a block: /unblock ads.example"),
    ("allow", "Allow one exact domain: /allow cdn.example (or /allow wild ...)"),
    ("unallow", "Remove an allow: /unallow cdn.example"),
    ("pause", "Pause blocking for N minutes (default 5, max 60)"),
    ("resume", "Turn blocking back on"),
    ("name", "Name a device: /name <device> <new name>"),
    ("group", "Put a device in a group: /group <device> <group> [remove]"),
    ("mute", "Hold instant alerts: /mute 1h (30m, 8h, 1d; up to 7d)"),
    ("unmute", "Send held alerts now and stop holding"),
    ("quiet", "Quiet hours: /quiet 23:00-07:00, or /quiet off"),
    ("push", "Instant alerts on or off: /push off"),
    ("settings", "Show the thresholds you can change"),
    ("set", "Change one: /set NXDOMAIN_THRESHOLD 30"),
    ("unset", "Go back to the .env value: /unset NXDOMAIN_THRESHOLD"),
    ("help", "What I can do"),
]
# Commands that change something; refused when older than STALE_SECONDS.
WRITE_COMMANDS = {"block", "unblock", "allow", "unallow", "pause", "resume", "name", "group",
                  "mute", "unmute", "quiet", "push", "set", "unset"}
MAX_PAUSE_MINUTES = 60
STALE_SECONDS = 300
ONLINE_SECONDS = 900
MAX_REPORT_DAYS = 30


APEX = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")


def wild_regex(domain: str) -> str:
    """Pi-hole's regex for a domain and all its subdomains, as `pihole --wild` writes it."""
    return r"(\.|^)" + domain.replace(".", r"\.") + "$"


def alert_ident(alert) -> str:
    """The device an alert is about: dedup keys are "rule|ident[|apex]"."""
    parts = alert.dedup.split("|")
    return parts[1] if len(parts) > 1 else alert.client


def mute_key(rule: str, ident: str) -> str:
    return f"mute:{rule}|{ident}"


def is_muted(state, alert, now: float) -> bool:
    return (state.get(mute_key(alert.rule, alert_ident(alert))) or 0) > now


def action_button(state, label: str, payload: dict, now: float, style: str | None = None) -> dict:
    btn = {"text": label, "callback_data": f"a:{state.add_action(payload, now)}"}
    if style:
        btn["style"] = style
    return btn


def alert_buttons(state, alert, now: float) -> list[list[dict]]:
    """Block (when the domain resolved), mute this rule for this device, and the NAS command to copy."""
    rows = []
    command = (alert.evidence or {}).get("block")
    target = command.rsplit(" ", 1)[-1] if command else ""
    if APEX.fullmatch(target):
        rows.append([action_button(state, f"🛡 Block {target}", {"kind": "block", "domain": target}, now, "danger")])
    mute = {"kind": "mute", "rule": alert.rule, "ident": alert_ident(alert), "label": alert.client}
    rows.append([action_button(state, "🔕 Mute 24 h", {**mute, "hours": 24}, now),
                 action_button(state, "🔕 Mute 7 d", {**mute, "hours": 168}, now)])
    if command and len(command) <= 256:  # copy_text holds 1-256 characters
        rows.append([{"text": "📋 Copy block command", "copy_text": {"text": command}}])
    return rows


QUIET = re.compile(r"([01]?\d|2[0-3]):([0-5]\d)-([01]?\d|2[0-3]):([0-5]\d)")
MAX_HELD = 200
MAX_MUTE = 7 * 86400


def in_quiet(quiet: str | None, now: float) -> bool:
    """Is local time inside "HH:MM-HH:MM"? A range like 23:00-07:00 crosses midnight."""
    match = QUIET.fullmatch(quiet or "")
    if not match:
        return False
    h1, m1, h2, m2 = map(int, match.groups())
    start, end = h1 * 60 + m1, h2 * 60 + m2
    local = time.localtime(now)
    minute = local.tm_hour * 60 + local.tm_min
    return start <= minute < end if start <= end else minute >= start or minute < end


def hold_reason(state, now: float) -> str | None:
    """Why HIGH pushes are being held right now: "muted", "quiet" or None."""
    if (state.get("bot:mute_until") or 0) > now:
        return "muted"
    if in_quiet(state.get("bot:quiet"), now):
        return "quiet"
    return None


def hold(state, alert) -> None:
    held = state.get("bot:held") or []
    held.append(alert.to_dict())
    state.put("bot:held", held[-MAX_HELD:])
    if not state.get("bot:held_reason"):
        state.put("bot:held_reason", hold_reason(state, alert.time))


def held_summary(state, held: list[dict], now: float) -> tuple[str, list]:
    """One message for everything /mute or quiet hours held back, with a Block button per domain."""
    reason = state.get("bot:held_reason")
    opener = "While you were muted" if reason == "muted" else "While it was quiet"
    lines = [f"🔔 <b>{opener}: {len(held)} alert{'' if len(held) == 1 else 's'}</b>", ""]
    for r in held[:20]:
        title = RULES.get(r["rule"], (r["rule"], ""))[0]
        domain = f" · <code>{esc(r['domain'])}</code>" if r.get("domain") else ""
        lines.append(f"{SEVERITY_ICON.get(r['severity'], '⚪')} {esc(when(r['time']))} · {esc(r.get('client'))} · "
                     f"{esc(title)}{domain}")
    if len(held) > 20:
        lines.append(f"<i>+{len(held) - 20} more in the daily report</i>")
    targets = []
    for r in held:
        command = (r.get("evidence") or {}).get("block") or ""
        target = command.rsplit(" ", 1)[-1]
        if APEX.fullmatch(target) and target not in targets:
            targets.append(target)
    buttons = [[action_button(state, f"🛡 Block {t}", {"kind": "block", "domain": t}, now, "danger")]
               for t in targets[:10]]
    return _fit("\n".join(lines)), buttons


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
    def __init__(self, det, api, telegram, started: float | None = None, env=None):
        self.det, self.api, self.telegram = det, api, telegram
        self.started = started if started is not None else time.time()
        self.owner = str(det.cfg.telegram_chat_id)
        self.env = os.environ if env is None else env  # the .env values /unset goes back to
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
        return action_button(self.det.state, label, payload, now, style)

    # alert buttons --------------------------------------------------------------------------
    def press_block(self, payload: dict, now: float) -> str:
        domain = payload["domain"]
        try:
            self.api.add_domain("deny", "regex", wild_regex(domain), comment=f"Telegram, {when(now)}")
        except Exception as exc:
            self.reply(f"⚠️ Couldn't block <code>{esc(domain)}</code>: {esc(exc)}")
            return f"Couldn't block: {exc}"[:200]
        undo = self.button("↩️ Undo", {"kind": "unblock", "domain": domain}, now)
        self.reply(f"🛡 Blocked <code>{esc(domain)}</code> and all its subdomains for everyone.", buttons=[[undo]])
        return "Blocked"

    def press_unblock(self, payload: dict, now: float) -> str:
        domain = payload["domain"]
        try:
            self.api.delete_domain("deny", "regex", wild_regex(domain))
        except Exception as exc:
            self.reply(f"⚠️ Couldn't unblock <code>{esc(domain)}</code>: {esc(exc)}")
            return f"Couldn't unblock: {exc}"[:200]
        self.reply(f"↩️ Unblocked <code>{esc(domain)}</code>.")
        return "Unblocked"

    def press_mute(self, payload: dict, now: float) -> str:
        hours = payload["hours"]
        self.det.state.put(mute_key(payload["rule"], payload["ident"]), now + hours * 3600)
        title = RULES.get(payload["rule"], (payload["rule"], ""))[0]
        span = f"{hours // 24} d" if hours >= 48 else f"{hours} h"
        undo = self.button("↩️ Undo", {**payload, "kind": "unmute"}, now)
        self.reply(f"🔕 Muted <b>{esc(title)}</b> for {esc(payload['label'])} for {span}, until "
                   f"{esc(when(now + hours * 3600))}. Those alerts are still logged and in the daily report.",
                   buttons=[[undo]])
        return f"Muted for {span}"

    def press_unmute(self, payload: dict, now: float) -> str:
        self.det.state.put(mute_key(payload["rule"], payload["ident"]), 0)
        title = RULES.get(payload["rule"], (payload["rule"], ""))[0]
        self.reply(f"🔔 Unmuted <b>{esc(title)}</b> for {esc(payload['label'])}.")
        return "Unmuted"

    def press_undo_rotation(self, payload: dict, now: float) -> str:
        path = self.det.cfg.client_changes_path
        change, why_not = clientlog.pick(clientlog.read(path), payload["time"])
        if not change:
            self.reply(f"↩️ Not undone: {esc(why_not)}.")
            return why_not[:200]
        try:
            clientlog.undo(change, self.api, path, now)
        except Exception as exc:
            self.reply(f"⚠️ Undo failed part-way: {esc(exc)}. Check Pi-hole > Clients.")
            return "Undo failed"
        restored = ", ".join(e["mac"] for e in change["deleted"]) or "nothing"
        self.reply(f"↩️ Undone for {esc(change['name'])}: removed <code>{change['added']['mac']}</code>, "
                   f"restored {esc(restored)}.")
        return "Undone"

    # changes, as undoable lists of ops ------------------------------------------------------
    # An op is a JSON list: ["add_domain", type, kind, domain], ["delete_domain", type, kind, domain],
    # ["add_client" | "update_client", client, comment, groups], ["delete_client", client],
    # ["blocking", enabled, timer]. A change runs its ops; its Undo button holds the inverse ops.
    def _apply(self, ops: list, now: float, command: str) -> None:
        done = []
        try:
            for op in ops:
                name, *args = op
                if name == "add_domain":
                    self.api.add_domain(*args, comment=f"Telegram, {when(now)}")
                elif name == "delete_domain":
                    self.api.delete_domain(*args)
                elif name in ("add_client", "update_client"):
                    entry = Client(mac=args[0].lower(), client=args[0], comment=args[1], groups=tuple(args[2]))
                    (self.api.add_client if name == "add_client" else self.api.update_client)(entry)
                elif name == "delete_client":
                    self.api.delete_client(args[0])
                elif name == "blocking":
                    self.api.set_blocking(args[0], args[1])
                else:
                    raise ValueError(f"unknown op {name}")
                done.append(op)
        finally:
            if done:
                with Path(self.det.cfg.pihole_changes_path).open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps({"time": now, "command": command, "ops": done}) + "\n")

    def _change(self, command: str, ops: list, undo: list | None, text: str, now: float,
                undo_label: str = "↩️ Undo") -> bool:
        try:
            self._apply(ops, now, command)
        except Exception as exc:
            self.reply(f"⚠️ Pi-hole refused that: {esc(exc)}")
            return False
        buttons = [[self.button(undo_label, {"kind": "ops", "ops": undo, "command": "undo",
                                             "text": "↩️ Undone."}, now)]] if undo else None
        self.reply(text, buttons=buttons)
        return True

    def press_ops(self, payload: dict, now: float) -> str:
        """An Undo, or a confirmed change: run the stored ops."""
        ok = self._change(payload["command"], payload["ops"], payload.get("undo"), payload["text"], now)
        return "Done" if ok else "Failed"

    def _domain_arg(self, args, usage: str) -> tuple[str | None, str | None]:
        """(mode, domain) from "[exact|wild] <domain>", or (None, None) after replying with usage."""
        mode = args[0].lower() if args and args[0].lower() in ("exact", "wild") else None
        rest = args[1:] if mode else args
        domain = rest[0].lower().rstrip(".") if len(rest) == 1 else ""
        if not APEX.fullmatch(domain):
            self.reply(f"Usage: {esc(usage)}\nGive one plain domain, like <code>ads.example.com</code>: "
                       "no wildcards, spaces or regex.")
            return None, None
        return mode, domain

    def cmd_block(self, args, now) -> None:
        mode, domain = self._domain_arg(args, "/block <domain>  or  /block exact <domain>")
        if not domain:
            return
        if mode == "exact":
            op, what = ["deny", "exact", domain], f"<code>{esc(domain)}</code> (that exact name)"
        else:
            target = apex(domain)
            op, what = ["deny", "regex", wild_regex(target)], f"<code>{esc(target)}</code> and all its subdomains"
        self._change(f"/block {' '.join(args)}", [["add_domain", *op]], [["delete_domain", *op]],
                     f"🛡 Blocked {what} for everyone.", now)

    def cmd_allow(self, args, now) -> None:
        mode, domain = self._domain_arg(args, "/allow <domain>  or  /allow wild <domain>")
        if not domain:
            return
        if mode == "wild":
            target = apex(domain)
            op, what = ["allow", "regex", wild_regex(target)], f"<code>{esc(target)}</code> and all its subdomains"
        else:
            op, what = ["allow", "exact", domain], f"<code>{esc(domain)}</code> (that exact name)"
        self._change(f"/allow {' '.join(args)}", [["add_domain", *op]], [["delete_domain", *op]],
                     f"✅ Allowed {what} for everyone.", now)

    def _remove_listed(self, list_type: str, args, now) -> None:
        """Remove every entry the bot could have added for this domain (exact and wildcard)."""
        _, domain = self._domain_arg(args, f"/un{'block' if list_type == 'deny' else 'allow'} <domain>")
        if not domain:
            return
        removed = []
        for kind, value in (("regex", wild_regex(apex(domain))), ("exact", domain)):
            try:
                self._apply([["delete_domain", list_type, kind, value]], now, f"/un{list_type} {domain}")
                removed.append(["add_domain", list_type, kind, value])
            except Exception:
                continue  # not on the list in that form
        listed = "deny" if list_type == "deny" else "allow"
        if not removed:
            self.reply(f"<code>{esc(domain)}</code> wasn't on Pi-hole's {listed} list, as an exact name or with subdomains.")
            return
        undo = self.button("↩️ Undo", {"kind": "ops", "ops": removed, "command": "undo", "text": "↩️ Undone."}, now)
        verb = "Unblocked" if list_type == "deny" else "Removed the allow for"
        self.reply(f"{'🔓' if list_type == 'deny' else '🚫'} {verb} <code>{esc(domain)}</code>.", buttons=[[undo]])

    def cmd_unblock(self, args, now) -> None:
        self._remove_listed("deny", args, now)

    def cmd_unallow(self, args, now) -> None:
        self._remove_listed("allow", args, now)

    def cmd_pause(self, args, now) -> None:
        try:
            minutes = int(args[0]) if args else 5
        except ValueError:
            minutes = 5
        minutes = 5 if minutes < 1 else minutes
        capped = minutes > MAX_PAUSE_MINUTES
        minutes = min(minutes, MAX_PAUSE_MINUTES)
        note = f" ({MAX_PAUSE_MINUTES} min is the most I'll pause)" if capped else ""
        self._change(f"/pause {minutes}", [["blocking", False, minutes * 60]], [["blocking", True, None]],
                     f"⏸ Blocking paused for {minutes} min{note}. Pi-hole turns it back on by itself, "
                     f"at {esc(when(now + minutes * 60))}.", now, undo_label="▶️ Resume now")

    def cmd_resume(self, args, now) -> None:
        self._change("/resume", [["blocking", True, None]], None, "▶️ Blocking is on again.", now)

    def _targets(self, query: str) -> tuple[list, str | None]:
        """The device(s) a /name or /group means: one device, or one device on several MACs."""
        try:
            devices = [d for d in self.api.devices() if d.is_real_mac]
        except Exception as exc:
            return [], f"🚨 Couldn't ask Pi-hole for its devices ({esc(type(exc).__name__)})."
        found = self._find(query, devices)
        if not found:
            return [], f"No device matches <code>{esc(query)}</code>. Try /devices all."
        if len(found) > 1 and len({name_key(self._name(d)) for d in found}) > 1:
            listed = "\n".join(f"• {esc(self._name(d))} - <code>{d.hwaddr}</code>" for d in found[:15])
            return [], f"Several devices match:\n{listed}\n\nAsk again with the MAC."
        return found, None

    def cmd_name(self, args, now) -> None:
        if len(args) < 2:
            self.reply("Usage: /name <device> <new name>, e.g. /name 192.168.18.136 Living room AP")
            return
        targets, problem = self._targets(args[0])
        if problem:
            self.reply(problem)
            return
        new_name = " ".join(args[1:])[:100]
        entries = {c.mac: c for c in self.api.clients()}
        ops, undo = [], []
        for dev in targets:
            entry = entries.get(dev.hwaddr)
            if entry:
                ops.append(["update_client", entry.client, new_name, list(entry.groups)])
                undo.append(["update_client", entry.client, entry.comment, list(entry.groups)])
            else:
                ops.append(["add_client", dev.hwaddr, new_name, [0]])
                undo.append(["delete_client", dev.hwaddr])
        macs = ", ".join(f"<code>{d.hwaddr}</code>" for d in targets)
        self._change(f"/name {' '.join(args)}", ops, undo, f"🏷 Named {macs} <b>{esc(new_name)}</b> in Pi-hole Clients.", now)

    def cmd_group(self, args, now) -> None:
        remove = len(args) >= 3 and args[-1].lower() == "remove"
        if len(args) < 2 or len(args) > 3 or (len(args) == 3 and not remove):
            self.reply("Usage: /group <device> <group> [remove], e.g. /group 192.168.18.136 IoT")
            return
        groups = self.api.groups()
        gid = next((g for g, n in groups.items() if n.casefold() == args[1].casefold()), None)
        if gid is None:
            self.reply(f"There's no group <code>{esc(args[1])}</code>. Pi-hole has: "
                       f"{esc(', '.join(groups.values()))}.")
            return
        if remove and gid == 0:
            self.reply("Devices always stay in Default: a client outside Default gets none of its blocklists, "
                       "so it would silently lose all blocking.")
            return
        targets, problem = self._targets(args[0])
        if problem:
            self.reply(problem)
            return
        entries = {c.mac: c for c in self.api.clients()}
        ops, undo = [], []
        for dev in targets:
            entry = entries.get(dev.hwaddr)
            have = set(entry.groups) if entry else {0}
            want = sorted(have - {gid} if remove else have | {0, gid})
            if entry:
                ops.append(["update_client", entry.client, entry.comment, want])
                undo.append(["update_client", entry.client, entry.comment, list(entry.groups)])
            elif not remove:
                ops.append(["add_client", dev.hwaddr, self._name(dev), want])
                undo.append(["delete_client", dev.hwaddr])
        label, name = esc(self._name(targets[0])), esc(groups[gid])
        if not ops:
            self.reply(f"{label} isn't in {name}.")
            return
        command = f"/group {' '.join(args)}"
        if remove:
            confirm = self.button(f"✅ Remove from {groups[gid]}", {
                "kind": "ops", "ops": ops, "undo": undo, "command": command,
                "text": f"👥 Removed {label} from <b>{name}</b>."}, now, style="danger")
            self.reply(f"Remove {label} from <b>{name}</b>? That changes which lists block things for it.",
                       buttons=[[confirm]])
            return
        self._change(command, ops, undo, f"👥 Added {label} to <b>{name}</b> (and kept Default).", now)

    # alert settings -------------------------------------------------------------------------
    def cmd_mute(self, args, now) -> None:
        match = re.fullmatch(r"(\d+)\s*([mhd])", args[0].lower()) if args else None
        seconds = int(match[1]) * {"m": 60, "h": 3600, "d": 86400}[match[2]] if match else 3600
        seconds = min(max(seconds, 60), MAX_MUTE)
        self.det.state.put("bot:mute_until", now + seconds)
        unmute = self.button("🔔 Unmute now", {"kind": "unmute_all"}, now)
        self.reply(f"🔕 Instant alerts held until {esc(when(now + seconds))}. They're still logged, and you'll "
                   "get them in one message when it ends. Health and rotation messages still come through.",
                   buttons=[[unmute]])

    def cmd_unmute(self, args, now) -> None:
        self.press_unmute_all({}, now)

    def press_unmute_all(self, payload: dict, now: float) -> str:
        self.det.state.put("bot:mute_until", 0)
        held = len(self.det.state.get("bot:held") or [])
        quiet = " Quiet hours still apply." if hold_reason(self.det.state, now) else ""
        self.reply(f"🔔 Unmuted.{quiet}" + (f" The {held} held alert{'s' if held != 1 else ''} follow." if held and not quiet else ""))
        return "Unmuted"

    def cmd_quiet(self, args, now) -> None:
        state = self.det.state
        if not args:
            current = state.get("bot:quiet")
            self.reply(f"Quiet hours: {esc(current) if current else 'off'}. Set with /quiet 23:00-07:00, "
                       "or /quiet off.")
            return
        if args[0].lower() == "off":
            state.put("bot:quiet", None)
            self.reply("🔔 Quiet hours off.")
            return
        if not QUIET.fullmatch(args[0]):
            self.reply("Usage: /quiet HH:MM-HH:MM (24-hour, e.g. /quiet 23:00-07:00) or /quiet off")
            return
        state.put("bot:quiet", args[0])
        self.reply(f"🌙 Quiet hours {esc(args[0])}: instant alerts in that window are held and sent together "
                   "when it ends. Health and rotation messages still come through.")

    def cmd_push(self, args, now) -> None:
        if not args or args[0].lower() not in ("on", "off"):
            self.reply(f"Instant alerts are {'on' if self.det.cfg.push_enabled else 'off'}. Usage: /push on | off")
            return
        self.cmd_set(["PUSH_ENABLED", "true" if args[0].lower() == "on" else "false"], now)

    def _apply_setting(self, field_name: str, value) -> None:
        setattr(self.det.cfg, field_name, value)
        if field_name == "push_cap_per_hour":
            self.telegram.cap = value  # Telegram keeps its own copy of the cap

    def cmd_set(self, args, now) -> None:
        if len(args) < 2:
            self.reply("Usage: /set NAME value, e.g. /set NXDOMAIN_THRESHOLD 30. /settings lists the names.")
            return
        raw = " ".join(args[1:])
        try:
            field_name, value = parse_setting(args[0], raw)
        except ValueError as exc:
            self.reply(f"⚠️ {esc(exc)}. /settings lists what can be changed.")
            return
        self.det.state.put(f"setting:{field_name.upper()}", raw)
        self._apply_setting(field_name, value)
        shown = ", ".join(value) if isinstance(value, tuple) else value
        self.reply(f"⚙️ {field_name.upper()} = <code>{esc(shown)}</code> from now on, and after restarts. "
                   f"/unset {field_name.upper()} goes back to the .env value.")

    def cmd_unset(self, args, now) -> None:
        name = args[0].lower() if args else ""
        if name not in SETTABLE:
            self.reply("Usage: /unset NAME. /settings lists the names.")
            return
        self.det.state.put(f"setting:{name.upper()}", None)
        value = getattr(Config.from_env(self.env), name)
        self._apply_setting(name, value)
        shown = ", ".join(value) if isinstance(value, tuple) else value
        self.reply(f"⚙️ {name.upper()} is back to <code>{esc(shown)}</code>.")

    def cmd_settings(self, args, now) -> None:
        lines = ["⚙️ <b>Settings you can change</b> (/set NAME value)", ""]
        for name in SETTABLE:
            value = getattr(self.det.cfg, name)
            shown = ", ".join(value) if isinstance(value, tuple) else value
            mark = " · <i>set here</i>" if self.det.state.get(f"setting:{name.upper()}") is not None else ""
            lines.append(f"<code>{name.upper()}</code> = {esc(shown if shown != '' else '-')}{mark}")
        self.reply(_fit("\n".join(lines)))

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
        state = self.det.state
        mute_until, quiet = state.get("bot:mute_until") or 0, state.get("bot:quiet")
        if mute_until > now or quiet:
            parts = [f"Muted until {esc(when(mute_until))}"] if mute_until > now else []
            parts += [f"Quiet {esc(quiet)}" + (" (now)" if in_quiet(quiet, now) else "")] if quiet else []
            held = len(state.get("bot:held") or [])
            lines.append("🔕 " + " · ".join(parts) + (f" · {held} held" if held else ""))
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
