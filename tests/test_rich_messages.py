"""Pushes, the digest and /status are rich messages, and a message always arrives even when rich text can't."""

import pytest

from pihole_detector import sinks
from pihole_detector.bot import Bot
from pihole_detector.model import Alert
from pihole_detector.telegram import TelegramError
from conftest import T0, FakePihole, q

OWNER = 42
DAY = 86400
HEADLINE = "🔴 Test device looked up a known bad domain"
BLOCKS = [{"type": "heading", "text": HEADLINE, "size": 3},
          {"type": "paragraph", "text": {"type": "code", "text": "beacon.evil-c2.example"}},
          {"type": "details", "summary": "Details", "blocks": [{"type": "paragraph", "text": "Meaning."}]}]


def setup(make_detector, api=None, **cfg):
    api = api or FakePihole()
    cfg.setdefault("push_enabled", True)
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, api=api, rich_messages=True, **cfg)
    return Bot(det, api, det.telegram, started=T0), det, api


def sent(det):
    return det.telegram.payloads("sendRichMessage")


def body(payload):
    return payload["rich_message"]["html"]


def edits(det):
    return det.telegram.payloads("editMessageText")


def labels(payload):
    return [b["text"] for row in payload["reply_markup"]["inline_keyboard"] for b in row]


def button(payload, label):
    return next(b for row in payload["reply_markup"]["inline_keyboard"] for b in row if label in b["text"])


def message(text, date=T0):
    return {"update_id": 1, "message": {"message_id": 100, "date": int(date), "text": text,
                                        "chat": {"id": OWNER, "type": "private"}, "from": {"id": OWNER}}}


def press(bot, payload, label, blocks=None, now=T0 + 5):
    """Press a button the way Telegram reports it on a rich message: blocks, not text."""
    bot.handle({"update_id": 2, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": button(payload, label)["callback_data"],
        "message": {"message_id": 55, "date": int(T0), "chat": {"id": OWNER, "type": "private"},
                    "rich_message": {"blocks": blocks if blocks is not None else BLOCKS},
                    "reply_markup": payload["reply_markup"]}}}, now)


def failing(det, method):
    real = det.telegram._api

    def api(name, payload=None, files=None, timeout=10):
        if name == method:
            raise TelegramError(400)
        return real(name, payload, files, timeout)

    det.telegram._api = api


# --- a push -----------------------------------------------------------------------------------

def test_a_push_is_a_rich_message_with_its_buttons(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    assert det.telegram.messages == []
    html = body(sent(det)[0])
    assert html.startswith("<h3>🔴 ") and "<code>beacon.evil-c2.example</code>" in html
    assert "Block evil-c2.example" in labels(sent(det)[0]) and "Mute 24 h" in labels(sent(det)[0])


def test_a_push_shows_each_fact_once(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    assert body(sent(det)[0]).count("beacon.evil-c2.example") == 1


def test_the_details_are_folded_away(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    html = body(sent(det)[0])
    folded = html[html.index("<details>"):]
    assert "<summary>Details</summary>" in folded and "<table>" in folded and "evil-c2.example" in folded
    assert "threat-intelligence list" in folded


def test_only_block_is_coloured_and_it_is_blue(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    assert button(sent(det)[0], "Block")["style"] == "primary"
    assert "style" not in button(sent(det)[0], "Mute 24 h")


def test_a_bad_domain_is_never_turned_into_a_link(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    assert sent(det)[0]["rich_message"]["skip_entity_detection"] is True


def test_names_cannot_break_the_html():
    alert = Alert(time=T0, severity="HIGH", rule="ti_match", label="<b>TV & co", domain="a.example", message="m",
                  evidence={}, ips=("192.0.2.1",))
    assert "&lt;b&gt;TV &amp; co" in sinks.rich_push(alert)


def test_without_the_bot_a_push_carries_the_block_command(make_detector):
    det = make_detector(telegram_chat_id=str(OWNER), push_enabled=True, rich_messages=True)
    det.process_query(q("evil-c2.example"))
    assert "pihole --wild evil-c2.example" in body(sent(det)[0]) and "reply_markup" not in sent(det)[0]


def test_the_hourly_cap_counts_rich_messages(make_detector):
    _, det, _ = setup(make_detector, push_cap_per_hour=1, dedup_hours=0)
    for t in range(3):
        det.process_query(q("evil-c2.example", t=t))
    assert len(sent(det)) == 1 and "Too many alerts" in det.telegram.messages[0]


# --- when rich text can't be sent --------------------------------------------------------------

def test_a_rich_message_telegram_refuses_goes_out_as_text_with_its_buttons(make_detector):
    _, det, _ = setup(make_detector)
    failing(det, "sendRichMessage")
    det.process_query(q("evil-c2.example"))
    assert "known bad domain" in det.telegram.messages[0]
    assert "Block evil-c2.example" in labels(det.telegram.payloads()[0])


def test_the_setting_turns_rich_messages_off(make_detector):
    bot, det, _ = setup(make_detector)
    bot.handle(message("/set RICH_MESSAGES false"), T0)
    det.process_query(q("evil-c2.example"))
    assert sent(det) == [] and any("known bad domain" in m for m in det.telegram.messages)


# --- pressing a button ----------------------------------------------------------------------------

def test_block_changes_the_message_in_place_and_goes_green(make_detector):
    bot, det, api = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    before = len(det.telegram.messages)
    press(bot, sent(det)[0], "Block")
    assert api.calls and len(det.telegram.messages) == before and len(sent(det)) == 1
    edit = edits(det)[-1]
    blocks = edit["rich_message"]["blocks"]
    assert edit["message_id"] == 55 and edit["rich_message"]["skip_entity_detection"] is True
    assert blocks[0]["text"] == "🟢 Blocked evil-c2.example and its subdomains"
    assert blocks[1:] == BLOCKS[1:]
    assert "Undo block" in labels(edit) and "Mute 24 h" in labels(edit)


def test_undoing_a_block_brings_the_alert_back(make_detector):
    bot, det, api = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    press(bot, sent(det)[0], "Block")
    first = edits(det)[-1]
    press(bot, first, "Undo block", first["rich_message"]["blocks"])
    assert api.calls[-1][0] == "delete_domain"
    edit = edits(det)[-1]
    blocks = edit["rich_message"]["blocks"]
    assert blocks[0]["text"].startswith("🔴 ") and "known bad domain" in blocks[0]["text"]
    assert blocks[-1] == {"type": "paragraph", "text": "↩️ Unblocked evil-c2.example."}
    assert "Block evil-c2.example" in labels(edit)


def test_blocking_again_clears_the_unblocked_note(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    press(bot, sent(det)[0], "Block")
    undo = edits(det)[-1]
    press(bot, undo, "Undo block", undo["rich_message"]["blocks"])
    again = edits(det)[-1]
    press(bot, again, "Block", again["rich_message"]["blocks"])
    assert edits(det)[-1]["rich_message"]["blocks"] == [
        {**BLOCKS[0], "text": "🟢 Blocked evil-c2.example and its subdomains"}, *BLOCKS[1:]]


def test_mute_adds_a_line_and_keeps_the_heading(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    press(bot, sent(det)[0], "Mute 7 d")
    edit = edits(det)[-1]
    blocks = edit["rich_message"]["blocks"]
    assert blocks[0]["text"] == HEADLINE and blocks[-1]["text"].startswith("🔕 Muted")
    assert "Undo mute" in labels(edit)


def test_a_failed_edit_still_tells_the_owner(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    failing(det, "editMessageText")
    press(bot, sent(det)[0], "Block")
    assert "Blocked evil-c2.example" in det.telegram.messages[-1]


def test_a_button_on_an_old_picture_still_answers(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    payload = sent(det)[0]
    bot.handle({"update_id": 2, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": button(payload, "Block")["callback_data"],
        "message": {"message_id": 55, "date": int(T0), "chat": {"id": OWNER, "type": "private"},
                    "photo": [{"file_id": "x"}], "caption": "old", "reply_markup": payload["reply_markup"]}}}, T0 + 5)
    assert "Blocked evil-c2.example" in det.telegram.messages[-1]


# --- the digest ---------------------------------------------------------------------------------------

def test_a_busy_digest_is_a_rich_message_with_its_buttons(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("www.xk7qz9w2vb4m.com"))
    det.state.put("last_digest", T0 - DAY)
    assert det.maybe_digest(T0 + 60, force=True)
    payload = sent(det)[-1]
    assert "Block xk7qz9w2vb4m.com" in labels(payload) and "📄 Full report" in labels(payload)
    html = body(payload)
    assert "<h3>🟠 Digest: 1 alert needs a look</h3>" in html and "Random-looking domain" in html


def record(severity="MEDIUM", label="TV", rule="beaconing", **extra):
    return {"severity": severity, "rule": rule, "label": label, "domain": "a.example", "time": T0, "evidence": {},
            **extra}


def test_the_worst_alert_sets_the_digests_colour():
    html = sinks.rich_digest([record(), record("HIGH", rule="ti_match")], {"queries": 5}, T0, T0 + DAY)
    assert html.startswith("<h3>🔴 Digest: 2 alerts need a look</h3>")
    assert html.index("Malware / phishing domain") < html.index("Regular check-ins")


def test_low_alerts_are_folded_away_in_a_digest():
    html = sinks.rich_digest([record(), record("LOW", label="iPad", rule="device_silent")], {}, T0, T0 + DAY)
    assert html.index("<details>") < html.index("iPad") and "<summary>1 low alert</summary>" in html


def test_a_digest_of_only_low_alerts_has_nothing_to_look_at():
    html = sinks.rich_digest([record("LOW", label="iPad", rule="device_silent")], {}, T0, T0 + DAY)
    assert html.startswith("<h3>🟡 Digest: 1 low alert</h3>")


def test_repeats_of_one_alert_share_a_row():
    html = sinks.rich_digest([record() for _ in range(3)], {}, T0, T0 + DAY)
    assert html.count("<tr>") == 1 and "Regular check-ins ×3" in html


def test_a_huge_digest_stays_short_and_says_what_it_left_out():
    records = [record(label=f"device {i}") for i in range(60)]
    html = sinks.rich_digest(records, {"queries": 5}, T0, T0 + DAY)
    assert html.count("<tr>") == sinks.DIGEST_ROWS and f"+{60 - sinks.DIGEST_ROWS} more" in html


def test_failed_polls_are_shown_on_a_digest():
    assert "3 failed polls" in sinks.rich_digest([record()], {"api_failures": 3}, T0, T0 + DAY)


def test_a_quiet_digest_stays_one_line_of_text(make_detector):
    _, det, _ = setup(make_detector)
    det.state.put("last_digest", T0 - DAY)
    det.maybe_digest(T0, force=True)
    assert sent(det) == [] and det.telegram.messages[-1].startswith("✅ <b>Digest: nothing suspicious")


def test_a_refused_digest_still_counts_as_sent_as_text(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("www.xk7qz9w2vb4m.com"))
    det.state.put("last_digest", T0 - DAY)
    failing(det, "sendRichMessage")
    det.maybe_digest(T0 + 60, force=True)
    assert "Digest:" in det.telegram.messages[-1] and det.state.get("last_digest") == T0 + 60


def test_pressing_block_on_a_digest_keeps_its_heading(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("www.xk7qz9w2vb4m.com"))
    det.state.put("last_digest", T0 - DAY)
    det.maybe_digest(T0 + 60, force=True)
    digest = [{"type": "heading", "text": "🟠 Digest: 1 alert needs a look", "size": 3}]
    press(bot, sent(det)[-1], "Block xk7qz9w2vb4m.com", digest)
    blocks = edits(det)[-1]["rich_message"]["blocks"]
    assert blocks[0] == digest[0] and blocks[-1]["text"].startswith("🛡 Blocked xk7qz9w2vb4m.com")


# --- /status --------------------------------------------------------------------------------------

def test_status_is_calm_and_short_when_all_is_well(make_detector):
    bot, det, _ = setup(make_detector)
    bot.handle(message("/status"), T0)
    html = body(sent(det)[-1])
    assert html.startswith("<h3>🟢 All good</h3>") and "Up and blocking" in html and "None" in html
    assert html.index("<details>") < html.index("Detector")


def test_status_says_how_many_alerts(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("evil-c2.example"))
    bot.handle(message("/status"), T0)
    assert "1 high" in body(sent(det)[-1]) and "0 medium" not in body(sent(det)[-1])


def test_status_commands_stay_tappable(make_detector):
    bot, det, _ = setup(make_detector)
    bot.handle(message("/status"), T0)
    assert sent(det)[-1]["rich_message"]["skip_entity_detection"] is False


def test_status_with_pihole_down_still_answers(make_detector):
    bot, det, api = setup(make_detector)
    api.down = True
    bot.handle(message("/status"), T0)
    assert body(sent(det)[-1]).startswith("<h3>🚨 Pi-hole is not reachable</h3>")


def test_status_text_is_still_there_when_rich_messages_fail(make_detector):
    bot, det, _ = setup(make_detector)
    failing(det, "sendRichMessage")
    bot.handle(message("/status"), T0)
    assert det.telegram.messages[-1].startswith("✅ <b>Status: Pi-hole is up and blocking</b>")


@pytest.mark.parametrize("text", ["<b>", "a & b"])
def test_a_table_escapes_its_cells(text):
    assert sinks.esc(text) in sinks.table([(text, text)])
