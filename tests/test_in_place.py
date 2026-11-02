"""A press on a pushed alert changes that alert: the result sits beside its cause, and the chat stays short."""

import json

from pihole_detector.bot import Bot
from pihole_detector.cards import BLOCK_STATUS, MUTE_STATUS, set_status, swap_row
from pihole_detector.sinks import strip_html
from pihole_detector.telegram import TelegramError
from conftest import T0, FakePihole, q

OWNER = 42
ENTITIES = [{"type": "bold", "offset": 2, "length": 10}]
REGEX = r"(\.|^)evil-c2\.example$"
BLOCKED, UNBLOCKED = "Blocked evil-c2.example", "Unblocked evil-c2.example"


def setup(make_detector, api=None, **cfg):
    api = api or FakePihole()
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, push_enabled=True, api=api, **cfg)
    det.process_query(q("beacon.evil-c2.example"))
    return Bot(det, api, det.telegram, started=T0), det, api


def edits(det):
    return det.telegram.payloads("editMessageText")


def on_screen(det):
    """The alert as it stands: the latest edit, or the push itself."""
    return (edits(det) or det.telegram.payloads())[-1]


def labels(payload):
    return [button["text"] for row in payload["reply_markup"]["inline_keyboard"] for button in row]


def press(bot, det, label, now=T0 + 5):
    """Press a button the way Telegram reports it, with the message's own text, entities and keyboard."""
    shown = on_screen(det)
    rows = shown["reply_markup"]["inline_keyboard"]
    data = next(b["callback_data"] for row in rows for b in row if label in b["text"] and "callback_data" in b)
    bot.handle({"update_id": 2, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": data,
        "message": {"message_id": 55, "date": int(T0), "chat": {"id": OWNER, "type": "private"},
                    "text": strip_html(shown["text"]), "entities": shown.get("entities", ENTITIES),
                    "reply_markup": {"inline_keyboard": rows}}}}, now)


def test_block_changes_the_alert_instead_of_sending_a_message(make_detector):
    bot, det, api = setup(make_detector)
    sent = len(det.telegram.messages)
    press(bot, det, "Block")
    assert api.calls == [("add_domain", "deny", "regex", REGEX)]
    assert len(det.telegram.messages) == sent
    edit = edits(det)[-1]
    assert edit["message_id"] == 55 and BLOCKED in edit["text"]


def test_the_edit_keeps_the_alerts_text_and_formatting(make_detector):
    bot, det, _ = setup(make_detector)
    original = strip_html(det.telegram.payloads()[-1]["text"])
    press(bot, det, "Block")
    edit = edits(det)[-1]
    assert edit["text"].startswith(original + "\n\n🛡 ")
    assert edit["entities"] == ENTITIES and "parse_mode" not in edit


def test_after_a_block_the_button_becomes_its_undo_and_the_mutes_stay(make_detector):
    bot, det, _ = setup(make_detector)
    press(bot, det, "Block")
    shown = labels(edits(det)[-1])
    assert "Undo block" in shown and "Mute 24 h" in shown and "Mute 7 d" in shown
    assert not any("Block evil" in label for label in shown)


def test_undoing_a_block_changes_the_alert_back(make_detector):
    bot, det, api = setup(make_detector)
    press(bot, det, "Block")
    press(bot, det, "Undo block")
    assert api.calls[-1] == ("delete_domain", "deny", "regex", REGEX)
    edit = edits(det)[-1]
    assert UNBLOCKED in edit["text"] and BLOCKED not in edit["text"].replace(UNBLOCKED, "")
    assert "Block evil-c2.example" in labels(edit)


def test_it_can_be_blocked_again_after_an_undo(make_detector):
    bot, det, api = setup(make_detector)
    press(bot, det, "Block")
    press(bot, det, "Undo block")
    press(bot, det, "Block")
    assert api.calls[-1] == ("add_domain", "deny", "regex", REGEX)
    assert edits(det)[-1]["text"].count("evil-c2.example and all its subdomains") == 1
    assert UNBLOCKED not in edits(det)[-1]["text"]


def test_a_block_and_its_undo_are_both_in_the_audit_log(make_detector, tmp_path):
    bot, det, _ = setup(make_detector)
    press(bot, det, "Block")
    press(bot, det, "Undo block")
    lines = [json.loads(line) for line in (tmp_path / "pihole_changes.jsonl").read_text().splitlines()]
    assert [line["ops"][0][0] for line in lines] == ["add_domain", "delete_domain"]


def test_mute_changes_the_alert_and_its_row_becomes_the_undo(make_detector):
    bot, det, _ = setup(make_detector)
    sent = len(det.telegram.messages)
    press(bot, det, "Mute 7 d")
    assert len(det.telegram.messages) == sent
    edit = edits(det)[-1]
    assert "🔕 Muted" in edit["text"] and "7 d" in edit["text"] and "in the digest" in edit["text"]
    assert "Undo mute" in labels(edit) and not any("Mute 24" in label for label in labels(edit))
    assert any("Block" in label for label in labels(edit))


def test_undoing_a_mute_brings_both_mute_buttons_back(make_detector):
    bot, det, _ = setup(make_detector, dedup_hours=0)
    press(bot, det, "Mute 24 h")
    press(bot, det, "Undo mute")
    edit = edits(det)[-1]
    assert "🔔 Unmuted" in edit["text"] and "🔕 Muted" not in edit["text"]
    assert "Mute 24 h" in labels(edit) and "Mute 7 d" in labels(edit)
    pushes = len(det.telegram.messages)
    det.process_query(q("other.evil-c2.example", t=60))
    assert len(det.telegram.messages) == pushes + 1  # really lifted


def test_block_and_mute_each_keep_their_own_status(make_detector):
    bot, det, _ = setup(make_detector)
    press(bot, det, "Block")
    press(bot, det, "Mute 24 h")
    press(bot, det, "Undo block")
    text = edits(det)[-1]["text"]
    assert "🔕 Muted" in text and UNBLOCKED in text and BLOCKED not in text.replace(UNBLOCKED, "")


def test_a_refused_block_leaves_the_alert_alone_and_says_why(make_detector):
    bot, det, _ = setup(make_detector, api=FakePihole(fail={"add_domain": "POST /domains/deny/regex: HTTP 400"}))
    press(bot, det, "Block")
    assert edits(det) == [] and "HTTP 400" in det.telegram.messages[-1]


def test_a_message_telegram_can_no_longer_show_gets_a_new_message(make_detector):
    bot, det, api = setup(make_detector)
    data = det.telegram.payloads()[-1]["reply_markup"]["inline_keyboard"][0][0]["callback_data"]
    bot.handle({"update_id": 2, "callback_query": {  # past 48 h Telegram sends no text or keyboard
        "id": "cb1", "from": {"id": OWNER}, "data": data,
        "message": {"message_id": 55, "date": 0, "chat": {"id": OWNER, "type": "private"}}}}, T0 + 5)
    assert api.calls and edits(det) == []
    assert BLOCKED in det.telegram.messages[-1] and "Undo block" in labels(det.telegram.payloads()[-1])


def test_a_failed_edit_still_tells_the_owner(make_detector):
    bot, det, _ = setup(make_detector)
    real = det.telegram._api

    def no_edits(method, payload=None, files=None, timeout=10):
        if method == "editMessageText":
            raise TelegramError(400)
        return real(method, payload, files, timeout)

    det.telegram._api = no_edits
    press(bot, det, "Block")
    assert BLOCKED in det.telegram.messages[-1]


def test_a_new_message_escapes_what_it_quotes(make_detector):
    bot, det, _ = setup(make_detector)
    bot.press_mute({"rule": "ti_match", "ident": "x", "label": "<TV>", "hours": 24}, T0)
    assert "&lt;TV&gt;" in det.telegram.messages[-1]


# --- the status lines and the keyboard, on their own --------------------------------------

def test_a_status_replaces_only_its_own_line():
    text = set_status("alert", BLOCK_STATUS, "a.example", "🛡 Blocked a.example")
    text = set_status(text, BLOCK_STATUS, "b.example", "🛡 Blocked b.example")
    text = set_status(text, BLOCK_STATUS, "a.example", "↩️ Unblocked a.example")
    assert text == "alert\n\n🛡 Blocked b.example\n↩️ Unblocked a.example"


def test_a_status_never_touches_the_alert_itself():
    text = "🔔 While you were muted\n🛡 notes on a.example"
    assert set_status(text, MUTE_STATUS, "", "🔕 Muted").startswith("🔔 While you were muted\n")


def test_only_the_pressed_row_is_swapped():
    rows = [[{"text": "a", "callback_data": "1"}], [{"text": "b", "callback_data": "2"}, {"text": "c", "callback_data": "3"}]]
    new = [{"text": "z", "callback_data": "9"}]
    assert swap_row(rows, "3", new) == [rows[0], new]
