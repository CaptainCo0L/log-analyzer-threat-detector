"""Buttons: one constructor per kind, and the payloads they store stay the shapes already on the owner's phone."""

import json

from pihole_detector.actions import Actions
from pihole_detector.bot import Bot
from pihole_detector.model import Alert
from pihole_detector.state import State
from conftest import PC_MAC, T0, FakePihole, press

ALERT = Alert(time=T0, severity="HIGH", rule="ti_match", label="AswinPC", domain="login.evil.example",
              device=PC_MAC, mac=PC_MAC, ips=("192.0.2.10",), dedup="d", message="m",
              evidence={"block": "pihole deny --wild evil.example"})
RECORD = json.loads(json.dumps(ALERT.to_dict()))  # as stored: tuples come back as lists


def stored(actions: Actions, button: dict) -> dict:
    """The payload a button stores (taking it, as a press would)."""
    return actions.state.take_action(button["callback_data"][2:], T0)


def test_each_kind_stores_the_payload_buttons_already_sent_carry():
    a = Actions(State(":memory:"))
    record = RECORD
    assert stored(a, a.block("evil.example", T0)) == {"kind": "block", "domain": "evil.example"}
    assert stored(a, a.block("evil.example", T0, record)) == {"kind": "block", "domain": "evil.example", "alert": record}
    assert stored(a, a.unblock("evil.example", T0, record)) == {"kind": "unblock", "domain": "evil.example",
                                                                  "alert": record}
    mute = {"rule": "ti_match", "ident": PC_MAC, "label": "AswinPC"}
    day, week = a.mute_row("ti_match", PC_MAC, "AswinPC", T0)
    assert stored(a, day) == {"kind": "mute", **mute, "hours": 24}
    assert stored(a, week) == {"kind": "mute", **mute, "hours": 168}
    assert stored(a, a.unmute("ti_match", PC_MAC, "AswinPC", 24, T0)) == {"kind": "unmute", **mute, "hours": 24}
    assert stored(a, a.ops("↩️ Undo", [["op"]], "undo", "Undone.", T0)) == {
        "kind": "ops", "ops": [["op"]], "command": "undo", "text": "Undone."}
    assert stored(a, a.ops("✅ Remove", [["op"]], "/group x IoT remove", "Removed.", T0, undo=[["back"]])) == {
        "kind": "ops", "ops": [["op"]], "undo": [["back"]], "command": "/group x IoT remove", "text": "Removed."}
    assert stored(a, a.unmute_all(T0)) == {"kind": "unmute_all"}
    assert stored(a, a.undo_rotation(T0 - 5, T0)) == {"kind": "undo_rotation", "time": T0 - 5}
    assert stored(a, a.full_report(7, T0, T0)) == {"kind": "full_report", "days": 7, "end": T0}


def test_a_button_is_taken_once():
    a = Actions(State(":memory:"))
    data = a.unmute_all(T0)["callback_data"]
    assert a.take(data, T0) == {"kind": "unmute_all"}
    assert a.take(data, T0) is None and a.take("not-ours", T0) is None


def test_alert_buttons_block_a_plain_domain_and_mute_the_rule_for_the_device():
    a = Actions(State(":memory:"))
    block, mutes = a.alert_buttons(ALERT, T0)
    assert block[0]["text"] == "Block evil.example" and block[0]["style"] == "primary"
    assert stored(a, block[0])["alert"] == RECORD
    assert [b["text"] for b in mutes] == ["Mute 24 h", "Mute 7 d"]


def test_pressing_payloads_written_before_the_actions_module_still_works(make_detector):
    """Buttons live a day, so ones sent by the previous deploy are pressed after this one."""
    api = FakePihole()
    det = make_detector(telegram_chat_id="42", api=api)
    bot = Bot(det, api, det.telegram, started=T0)
    old = [{"kind": "mute", "rule": "ti_match", "ident": PC_MAC, "label": "AswinPC", "hours": 24},
           {"kind": "ops", "ops": [["blocking", True, None]], "command": "undo", "text": "↩️ Undone."},
           {"kind": "full_report", "days": 1, "end": T0}]
    for i, payload in enumerate(old):
        bot.handle(press(f"a:{det.state.add_action(payload, T0)}", update_id=10 + i), T0 + 5)
    assert det.delivery.is_muted(ALERT, T0 + 5)
    assert ("blocking", True, None) in api.calls
    assert not any("expired" in m or "Unknown" in m for m in det.telegram.messages)
