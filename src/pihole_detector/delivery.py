"""Whether an alert reaches the phone: push it now, hold it for later, or leave it to the digest.

The detector hands every logged alert to `route`. Only HIGH alerts are ever pushed, and only with
PUSH_ENABLED on; a per-device mute drops them, /mute and quiet hours hold them for one summary
(`flush`), and more than PUSH_CAP_PER_HOUR in an hour pauses them with one notice. Everything else
(health, rotation, the digest, bot replies) goes out with `send`, which is never held or capped.
"""

from __future__ import annotations

import re
import time
from collections import deque

from .model import HIGH
from .sinks import RULES, SEVERITY_ICON, esc, fit, format_push, when

APEX = re.compile(r"[a-z0-9-]+(\.[a-z0-9-]+)+")  # a plain domain: safe to put in a Block button
QUIET = re.compile(r"([01]?\d|2[0-3]):([0-5]\d)-([01]?\d|2[0-3]):([0-5]\d)")
MAX_HELD = 200
MAX_MUTE = 7 * 86400

# state.db keys
MUTE_UNTIL, QUIET_HOURS, HELD, HELD_REASON = "bot:mute_until", "bot:quiet", "bot:held", "bot:held_reason"


def mute_key(rule: str, ident: str) -> str:
    return f"mute:{rule}|{ident}"


def alert_ident(alert) -> str:
    """The device an alert is about: dedup keys are "rule|ident[|apex]"."""
    parts = alert.dedup.split("|")
    return parts[1] if len(parts) > 1 else alert.client


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


def block_target(evidence: dict | None) -> str | None:
    """The domain an alert's block command would block, when it is a plain domain."""
    command = (evidence or {}).get("block") or ""
    target = command.rsplit(" ", 1)[-1]
    return target if APEX.fullmatch(target) else None


def action_button(state, label: str, payload: dict, now: float, style: str | None = None) -> dict:
    btn = {"text": label, "callback_data": f"a:{state.add_action(payload, now)}"}
    if style:
        btn["style"] = style
    return btn


def alert_buttons(state, alert, now: float) -> list[list[dict]]:
    """Block (when the domain resolved), mute this rule for this device, and the NAS command to copy."""
    rows = []
    command = (alert.evidence or {}).get("block")
    target = block_target(alert.evidence)
    if target:
        rows.append([action_button(state, f"🛡 Block {target}", {"kind": "block", "domain": target}, now, "danger")])
    mute = {"kind": "mute", "rule": alert.rule, "ident": alert_ident(alert), "label": alert.client}
    rows.append([action_button(state, "🔕 Mute 24 h", {**mute, "hours": 24}, now),
                 action_button(state, "🔕 Mute 7 d", {**mute, "hours": 168}, now)])
    if command and len(command) <= 256:  # copy_text holds 1-256 characters
        rows.append([{"text": "📋 Copy block command", "copy_text": {"text": command}}])
    return rows


class Delivery:
    def __init__(self, cfg, state, telegram):
        self.cfg, self.state, self.telegram = cfg, state, telegram
        self._pushed: deque[float] = deque()  # times of the pushes in the last hour
        self._over_cap = False

    # sending --------------------------------------------------------------------------------
    def send(self, text: str, buttons=None) -> bool:
        """A message that is not an alert push: never held, muted or capped."""
        return self.telegram.send(text, buttons=buttons)

    def button(self, label: str, payload: dict, now: float, style: str | None = None) -> dict:
        return action_button(self.state, label, payload, now, style)

    def route(self, alert) -> None:
        """An alert that was just logged: push it, hold it, or leave it to the digest."""
        if alert.severity != HIGH or not self.cfg.push_enabled or self.is_muted(alert, alert.time):
            return
        if self.hold_reason(alert.time):
            self._hold(alert)  # sent as one summary when /mute or quiet hours end
            return
        buttons = alert_buttons(self.state, alert, alert.time) if self.cfg.bot_enabled else None
        self._push(format_push(alert, hint=not buttons), alert.time, buttons)

    def _push(self, text: str, now: float, buttons) -> bool:
        while self._pushed and self._pushed[0] < now - 3600:
            self._pushed.popleft()
        cap = self.cfg.push_cap_per_hour
        if len(self._pushed) >= cap:
            if not self._over_cap:
                self._over_cap = True
                self.telegram.send(f"🔕 <b>Too many alerts</b>\n\nMore than {cap} in an hour, so instant "
                                   "alerts are paused for up to an hour. Everything is still logged and "
                                   "will be in the daily report.")
            return False
        self._over_cap = False
        self._pushed.append(now)
        return self.telegram.send(text, buttons=buttons)

    # holding --------------------------------------------------------------------------------
    def hold_reason(self, now: float) -> str | None:
        """Why HIGH pushes are being held right now: "muted", "quiet" or None."""
        if self.mute_until > now:
            return "muted"
        if in_quiet(self.quiet, now):
            return "quiet"
        return None

    def _hold(self, alert) -> None:
        held = self.state.get(HELD) or []
        held.append(alert.to_dict())
        self.state.put(HELD, held[-MAX_HELD:])
        if not self.state.get(HELD_REASON):
            self.state.put(HELD_REASON, self.hold_reason(alert.time))

    @property
    def held(self) -> int:
        return len(self.state.get(HELD) or [])

    def flush(self, now: float) -> bool:
        """Once /mute or quiet hours are over: one message with everything they held back."""
        held = self.state.get(HELD)
        if not held or self.hold_reason(now):
            return False
        text, buttons = self._held_summary(held, now)
        self.send(text, buttons)
        self.state.put(HELD, [])
        self.state.put(HELD_REASON, None)
        return True

    def _held_summary(self, held: list[dict], now: float) -> tuple[str, list]:
        """One message for everything held back, with a Block button per domain."""
        opener = "While you were muted" if self.state.get(HELD_REASON) == "muted" else "While it was quiet"
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
            target = block_target(r.get("evidence"))
            if target and target not in targets:
                targets.append(target)
        buttons = [[self.button(f"🛡 Block {t}", {"kind": "block", "domain": t}, now, "danger")]
                   for t in targets[:10]]
        return fit("\n".join(lines)), buttons

    # muting ---------------------------------------------------------------------------------
    def is_muted(self, alert, now: float) -> bool:
        return (self.state.get(mute_key(alert.rule, alert_ident(alert))) or 0) > now

    def mute(self, rule: str, ident: str, until: float) -> None:
        """Drop one rule's pushes for one device until `until` (0 lifts it)."""
        self.state.put(mute_key(rule, ident), until)

    @property
    def mute_until(self) -> float:
        return self.state.get(MUTE_UNTIL) or 0

    def mute_all(self, until: float) -> None:
        """Hold every push until `until` (0 lifts it; the held ones follow on the next flush)."""
        self.state.put(MUTE_UNTIL, until)

    @property
    def quiet(self) -> str | None:
        return self.state.get(QUIET_HOURS)

    def set_quiet(self, spec: str | None) -> None:
        """Daily quiet hours "HH:MM-HH:MM", or None for none."""
        if spec is not None and not QUIET.fullmatch(spec):
            raise ValueError(f"not HH:MM-HH:MM: {spec}")
        self.state.put(QUIET_HOURS, spec)
