"""Stage 2: buttons on pushed alerts, the rotation message and the daily report."""

import json
import time

from pihole_detector.bot import Bot, wild_regex
from pihole_detector.model import Device
from pihole_detector.rotation import Client
from conftest import PC_MAC, T0, FakePihole, q

OWNER = 42
DAY = 86400


def press(data, update_id=2):
    return {"update_id": update_id, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": data,
        "message": {"message_id": 55, "date": int(T0), "chat": {"id": OWNER, "type": "private"}}}}


def setup(make_detector, tmp_path, api=None, **cfg):
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, push_enabled=True,
                        client_changes_path=str(tmp_path / "client_changes.jsonl"), **cfg)
    api = api or FakePihole()
    det.clients_api = api
    return Bot(det, api, det.telegram, started=T0), det, api


def keyboard(payload):
    return [b for row in payload.get("reply_markup", {}).get("inline_keyboard", []) for b in row]


def button(det, label, message=-1):
    return next(b for b in keyboard(det.telegram.payloads()[message]) if label in b["text"])


# --- the wildcard regex --------------------------------------------------------------------

def test_wild_regex_matches_the_apex_and_its_subdomains_only():
    import re
    pattern = re.compile(wild_regex("evil-c2.example"))
    assert wild_regex("evil-c2.example") == r"(\.|^)evil-c2\.example$"
    assert pattern.search("evil-c2.example") and pattern.search("a.b.evil-c2.example")
    assert not pattern.search("notevil-c2.example") and not pattern.search("evil-c2.example.org")


# --- a pushed alert ------------------------------------------------------------------------

def test_an_unblocked_threat_push_has_block_mute_and_a_copyable_command(make_detector, tmp_path):
    bot, det, _ = setup(make_detector, tmp_path)
    det.process_query(q("beacon.evil-c2.example"))
    payload = det.telegram.payloads()[0]
    labels = [b["text"] for b in keyboard(payload)]
    assert any("Block evil-c2.example" in label for label in labels)
    assert button(det, "Block")["style"] == "danger"
    assert any("24 h" in label for label in labels) and any("7 d" in label for label in labels)
    copy = button(det, "Copy")
    assert copy["copy_text"]["text"] == "sudo docker exec pihole pihole --wild evil-c2.example"
    assert "run on the NAS" not in payload["text"]  # the button replaces the hint


def test_without_the_bot_the_push_keeps_the_text_hint_and_has_no_buttons(make_detector, tmp_path):
    det = make_detector(push_enabled=True)
    det.process_query(q("evil-c2.example"))
    payload = det.telegram.payloads()[0]
    assert "reply_markup" not in payload and "pihole --wild evil-c2.example" in payload["text"]


def test_a_blocked_threat_has_no_block_button(make_detector, tmp_path):
    bot, det, _ = setup(make_detector, tmp_path)
    det.process_query(q("evil-c2.example", status="GRAVITY", reply="BLOCKED"))
    labels = [b["text"] for b in keyboard(det.telegram.payloads()[0])]
    assert not any("Block" in label for label in labels) and any("Mute" in label for label in labels)


def test_block_adds_a_wildcard_deny_for_everyone_and_undo_removes_it(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    det.process_query(q("beacon.evil-c2.example"))
    bot.handle(press(button(det, "Block")["callback_data"]), T0 + 5)
    regex = r"(\.|^)evil-c2\.example$"
    assert api.calls == [("add_domain", "deny", "regex", regex)]
    assert "Blocked" in det.telegram.messages[-1] and "everyone" in det.telegram.messages[-1]
    bot.handle(press(button(det, "Undo")["callback_data"], update_id=3), T0 + 9)
    assert api.calls[-1] == ("delete_domain", "deny", "regex", regex)
    assert "Unblocked" in det.telegram.messages[-1]


def test_a_failed_block_says_why(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path, api=FakePihole(fail={"add_domain": "POST /domains/deny/regex: HTTP 400"}))
    det.process_query(q("evil-c2.example"))
    bot.handle(press(button(det, "Block")["callback_data"]), T0 + 5)
    toast = det.telegram.payloads("answerCallbackQuery")[-1]["text"]
    assert "HTTP 400" in toast or "HTTP 400" in det.telegram.messages[-1]


def test_mute_silences_that_rule_for_that_device_only_until_it_ends(make_detector, tmp_path):
    bot, det, _ = setup(make_detector, tmp_path, dedup_hours=0)
    det.process_query(q("evil-c2.example"))
    bot.handle(press(button(det, "24 h")["callback_data"]), T0 + 5)
    assert "Muted" in det.telegram.messages[-1]
    pushes = len(det.telegram.messages)
    det.process_query(q("other.evil-c2.example", t=60))           # same rule, same device: silent
    assert len(det.telegram.messages) == pushes
    assert det.alert_log.read()[-1]["domain"] == "other.evil-c2.example"  # but still logged for the report
    det.process_query(q("evil-c2.example", t=60, ip="192.0.2.20"))  # another device: pushed
    assert len(det.telegram.messages) == pushes + 1
    det.process_query(q("x.evil-c2.example", t=DAY + 60))         # mute over
    assert len(det.telegram.messages) == pushes + 2


def test_undo_on_a_mute_lifts_it(make_detector, tmp_path):
    bot, det, _ = setup(make_detector, tmp_path, dedup_hours=0)
    det.process_query(q("evil-c2.example"))
    bot.handle(press(button(det, "7 d")["callback_data"]), T0 + 5)
    bot.handle(press(button(det, "Undo")["callback_data"], update_id=3), T0 + 6)
    pushes = len(det.telegram.messages)
    det.process_query(q("evil-c2.example", t=60))
    assert len(det.telegram.messages) == pushes + 1


# --- the rotation message ------------------------------------------------------------------

IPAD_OLD, IPAD_NEW = "02:00:00:00:00:30", "06:00:00:00:00:31"


def rotate(det, api, new_mac=IPAD_NEW, now=T0 + 100, ip="192.0.2.31"):
    det.probe = lambda ips, wait, **_: {ip: {"mDNS": "Aswins-iPad"}}
    return det.process_devices([Device(hwaddr=new_mac, ips=(ip,), first_seen=now, last_query=now)], now)


def rotation_setup(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path, rotation_sync=True)
    det.names.update({IPAD_OLD: ("Aswins-iPad", "mDNS")}, T0)
    det.state.add_device(IPAD_OLD, T0)
    api.entries = [Client(mac=IPAD_OLD, client=IPAD_OLD.upper(), comment="iPad", groups=(0, 1))]
    return bot, det, api


def test_the_rotation_message_has_an_undo_button_that_reverses_it(make_detector, tmp_path):
    bot, det, api = rotation_setup(make_detector, tmp_path)
    rotate(det, api)
    undo = button(det, "Undo")
    api.calls.clear()
    bot.handle(press(undo["callback_data"]), T0 + 200)
    assert api.calls == [("delete_client", IPAD_NEW)]
    assert "Undone" in det.telegram.messages[-1]
    records = [json.loads(line) for line in (tmp_path / "client_changes.jsonl").read_text().splitlines()]
    assert "undo_of" in records[-1]


def test_undo_on_an_older_rotation_is_refused_while_a_newer_one_stands(make_detector, tmp_path):
    bot, det, api = rotation_setup(make_detector, tmp_path)
    rotate(det, api)
    first_undo = button(det, "Undo")
    newest = "0a:00:00:00:00:32"
    rotate(det, api, new_mac=newest, now=T0 + 300, ip="192.0.2.32")
    api.calls.clear()
    bot.handle(press(first_undo["callback_data"]), T0 + 400)
    assert api.calls == []
    assert "newer" in det.telegram.messages[-1]


# --- the daily report ----------------------------------------------------------------------

def test_the_daily_report_offers_the_full_report(make_detector, tmp_path):
    bot, det, _ = setup(make_detector, tmp_path)
    det.state.put("last_digest", T0 - DAY)
    det.maybe_digest(T0, force=True)
    full = button(det, "Full report")
    bot.handle(press(full["callback_data"]), T0 + 5)
    assert any(m == "sendDocument" for m, _, _ in det.telegram.calls)


def test_no_block_button_unless_the_target_is_a_plain_domain():
    from pihole_detector.delivery import alert_buttons
    from pihole_detector.model import Alert
    from pihole_detector.state import State
    for command in ("sudo docker exec pihole pihole --wild *", "sudo docker exec pihole pihole --wild a;b",
                    "sudo docker exec pihole pihole --wild localhost"):
        alert = Alert(time=T0, severity="HIGH", rule="ti_match", client="c", domain="d", message="m",
                      evidence={"block": command}, dedup="ti_match|c|d")
        labels = [b["text"] for row in alert_buttons(State(), alert, T0) for b in row]
        assert not any("Block" in label and "Copy" not in label for label in labels), command


def test_preview_sends_the_sample_alert_with_working_buttons_when_the_bot_is_on():
    from pihole_detector.__main__ import cmd_preview
    from pihole_detector.config import Config
    from pihole_detector.state import State
    from conftest import FakeTelegram
    tg, state = FakeTelegram(), State()
    assert cmd_preview(Config(bot_enabled=True, telegram_chat_id="42"), tg=tg, state=state) == 0
    first = tg.payloads()[0]
    assert "Example" in first["text"] and "--wild" not in first["text"]
    block = next(b for row in first["reply_markup"]["inline_keyboard"] for b in row if "Block" in b["text"])
    assert state.take_action(block["callback_data"][2:], time.time()) == {"kind": "block", "domain": "evil-c2.example"}
    tg2 = FakeTelegram()
    cmd_preview(Config(telegram_chat_id="42"), tg=tg2, state=State())
    assert "reply_markup" not in tg2.payloads()[0] and "pihole --wild evil-c2.example" in tg2.payloads()[0]["text"]
