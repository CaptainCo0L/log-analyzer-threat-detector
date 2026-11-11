"""Inline buttons: what each kind stores, and taking it back when the button is pressed.

A button's callback_data is only "a:<id>"; the payload lives in state.db for a day (State.add_action), and a
press takes it once. Each kind has one constructor here, so a payload is written one way, and the Bot's
`press_<kind>` reads it. Buttons sent by an earlier deploy are pressed after the next one, so a kind's
payload keeps its shape (tests/test_actions.py).
"""

from __future__ import annotations

from .delivery import block_target
from .model import HIGH
from .sinks import needs_attention

# Said the moment a button is pressed; the result then appears in the chat. Telegram allows one answer per press.
TOASTS = {"block": "Blocking…", "unblock": "Unblocking…", "mute": "Muting…", "unmute": "Unmuting…",
          "unmute_all": "Ending the hold…", "ops": "Working…", "undo_rotation": "Undoing…",
          "full_report": "Sending the full report…"}


class Actions:
    def __init__(self, state):
        self.state = state

    def take(self, data: str, now: float) -> dict | None:
        """The pressed button's payload, once: None for a second press, an expired one or one not ours."""
        return self.state.take_action(data[2:], now) if data.startswith("a:") else None

    def _button(self, label: str, payload: dict, now: float, style: str | None = None) -> dict:
        btn = {"text": label, "callback_data": f"a:{self.state.add_action(payload, now)}"}
        if style:
            btn["style"] = style
        return btn

    # Pi-hole's deny list --------------------------------------------------------------------
    def block(self, domain: str, now: float, alert: dict | None = None) -> dict:
        """Block the domain and its subdomains. `alert` (a pushed alert's record) brings its heading back on undo."""
        return self._button(f"Block {domain}", _with_alert({"kind": "block", "domain": domain}, alert), now, "primary")

    def unblock(self, domain: str, now: float, alert: dict | None = None) -> dict:
        return self._button("Undo block", _with_alert({"kind": "unblock", "domain": domain}, alert), now)

    # mutes ----------------------------------------------------------------------------------
    def mute_row(self, rule: str, ident: str, label: str, now: float) -> list[dict]:
        """Mute this rule for this device for a day, or a week."""
        mute = {"kind": "mute", "rule": rule, "ident": ident, "label": label}
        return [self._button("Mute 24 h", {**mute, "hours": 24}, now),
                self._button("Mute 7 d", {**mute, "hours": 168}, now)]

    def unmute(self, rule: str, ident: str, label: str, hours: int, now: float) -> dict:
        payload = {"kind": "unmute", "rule": rule, "ident": ident, "label": label, "hours": hours}
        return self._button("Undo mute", payload, now)

    def unmute_all(self, now: float) -> dict:
        """End the /mute hold."""
        return self._button("🔔 End the hold", {"kind": "unmute_all"}, now)

    # changes --------------------------------------------------------------------------------
    def ops(self, label: str, ops: list, command: str, text: str, now: float, undo: list | None = None,
            style: str | None = None) -> dict:
        """Run these ops (changes.py) and reply `text`: an Undo, or a change that asked to be confirmed."""
        payload: dict = {"kind": "ops", "ops": ops}
        if undo is not None:
            payload["undo"] = undo
        return self._button(label, {**payload, "command": command, "text": text}, now, style)

    def undo_rotation(self, time: float, now: float) -> dict:
        """Undo the rotation sync made at `time`."""
        return self._button("↩️ Undo", {"kind": "undo_rotation", "time": time}, now)

    # reports --------------------------------------------------------------------------------
    def full_report(self, days: int, end: float, now: float) -> dict:
        return self._button("📄 Full report", {"kind": "full_report", "days": days, "end": end}, now)

    # rows for whole messages ----------------------------------------------------------------
    def alert_buttons(self, alert, now: float) -> list[list[dict]]:
        """Block when the domain resolved, else the NAS command to copy, then mute this rule for this device."""
        rows = []
        command = (alert.evidence or {}).get("block")
        target = block_target(alert.evidence)
        if target:
            rows.append([self.block(target, now, alert.to_dict())])
        elif command and len(command) <= 256:  # copy_text holds 1-256 characters
            rows.append([{"text": "📋 Copy block command", "copy_text": {"text": command}}])
        rows.append(self.mute_row(alert.rule, alert.device, alert.label, now))
        return rows

    def block_rows(self, records: list[dict], now: float, limit: int) -> list[list[dict]]:
        """One Block button per domain that needs attention, HIGH alerts first."""
        urgent = sorted((r for r in records if needs_attention(r)), key=lambda r: r["severity"] != HIGH)
        targets = dict.fromkeys(t for r in urgent if (t := block_target(r.get("evidence"))))
        return [[self.block(t, now)] for t in list(targets)[:limit]]


def _with_alert(payload: dict, alert: dict | None) -> dict:
    return {**payload, "alert": alert} if alert is not None else payload
