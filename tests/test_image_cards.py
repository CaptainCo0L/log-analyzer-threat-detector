"""Pushes, the digest and /status go out as pictures, and a message always arrives even when a picture can't."""

import json

from pihole_detector import drawing
from pihole_detector.bot import Bot
from pihole_detector.model import Alert
from pihole_detector.sinks import strip_html
from pihole_detector.telegram import TelegramError
from conftest import T0, FakePihole, q

OWNER = 42
DAY = 86400
BLOCKED = "Blocked evil-c2.example"
ENTITIES = [{"type": "expandable_blockquote", "offset": 40, "length": 20}]


def setup(make_detector, api=None, **cfg):
    api = api or FakePihole()
    cfg.setdefault("push_enabled", True)
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, api=api, image_cards=True, **cfg)
    return Bot(det, api, det.telegram, started=T0), det, api


def photos(det):
    return det.telegram.payloads("sendPhoto")


def sent_files(det, method):
    return [files for m, _, files in det.telegram.calls if m == method]


def keyboard(payload):
    markup = payload["reply_markup"]
    return (json.loads(markup) if isinstance(markup, str) else markup)["inline_keyboard"]


def labels(payload):
    return [b["text"] for row in keyboard(payload) for b in row]


def message(text, date=T0):
    return {"update_id": 1, "message": {"message_id": 100, "date": int(date), "text": text,
                                        "chat": {"id": OWNER, "type": "private"}, "from": {"id": OWNER}}}


def press_on_photo(bot, payload, label, now=T0 + 5):
    """Press a button the way Telegram reports it for a photo: a caption, not text."""
    rows = keyboard(payload)
    data = next(b["callback_data"] for row in rows for b in row if label in b["text"] and "callback_data" in b)
    bot.handle({"update_id": 2, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": data,
        "message": {"message_id": 55, "date": int(T0), "chat": {"id": OWNER, "type": "private"},
                    "photo": [{"file_id": "x"}], "caption": strip_html(payload["caption"]),
                    "caption_entities": ENTITIES, "reply_markup": {"inline_keyboard": rows}}}}, now)


def failing(det, method):
    real = det.telegram._api

    def api(name, payload=None, files=None, timeout=10):
        if name == method:
            raise TelegramError(400)
        return real(name, payload, files, timeout)

    det.telegram._api = api


# --- a push -----------------------------------------------------------------------------------

def test_a_push_is_a_picture_with_its_buttons(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    assert det.telegram.messages == []
    photo = photos(det)[0]
    assert sent_files(det, "sendPhoto")[0]["photo"][1].startswith(b"\x89PNG")
    assert "🛡 Block evil-c2.example" in labels(photo) and "🔕 Mute 24 h" in labels(photo)


def test_the_caption_keeps_what_the_card_leaves_out(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    caption = photos(det)[0]["caption"]
    assert "<code>beacon.evil-c2.example</code>" in caption
    assert "<blockquote expandable>" in caption and "List entry: evil-c2.example" in caption
    assert photos(det)[0]["parse_mode"] == "HTML"


def test_without_the_bot_the_caption_carries_the_block_command(make_detector):
    det = make_detector(telegram_chat_id=str(OWNER), push_enabled=True, image_cards=True)
    det.process_query(q("evil-c2.example"))
    assert "pihole --wild evil-c2.example" in photos(det)[0]["caption"] and "reply_markup" not in photos(det)[0]


def test_a_caption_stays_within_telegrams_limit(make_detector):
    from pihole_detector.sinks import push_caption
    alert = Alert(time=T0, severity="HIGH", rule="ti_match", label="x" * 2000, domain="y" * 2000, message="m",
                  evidence={"matched": "z" * 2000}, ips=("192.0.2.1",))
    assert len(push_caption(alert)) <= 1024


def test_the_hourly_cap_counts_pictures(make_detector):
    _, det, _ = setup(make_detector, push_cap_per_hour=1, dedup_hours=0)
    for t in range(3):
        det.process_query(q("evil-c2.example", t=t))
    assert len(photos(det)) == 1 and "Too many alerts" in det.telegram.messages[0]


# --- when a picture can't be sent --------------------------------------------------------------

def test_a_card_that_cannot_be_drawn_goes_out_as_text(make_detector, monkeypatch):
    _, det, _ = setup(make_detector)

    def broken(*args, **kwargs):
        raise OSError("font missing")

    monkeypatch.setattr(drawing, "alert_card", broken)
    det.process_query(q("evil-c2.example"))
    assert photos(det) == [] and "known bad domain" in det.telegram.messages[0]


def test_a_picture_telegram_refuses_goes_out_as_text(make_detector):
    _, det, _ = setup(make_detector)
    failing(det, "sendPhoto")
    det.process_query(q("evil-c2.example"))
    assert "known bad domain" in det.telegram.messages[0]
    assert "Block evil-c2.example" in str(det.telegram.payloads()[0]["reply_markup"])


def test_the_setting_turns_pictures_off(make_detector):
    bot, det, _ = setup(make_detector)
    bot.handle(message("/set IMAGE_CARDS false"), T0)
    det.process_query(q("evil-c2.example"))
    assert photos(det) == [] and any("known bad domain" in m for m in det.telegram.messages)


# --- pressing a button ----------------------------------------------------------------------------

def test_block_redraws_the_card_and_changes_nothing_else(make_detector):
    bot, det, api = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    sent = len(det.telegram.messages)
    press_on_photo(bot, photos(det)[0], "Block")
    assert api.calls and len(det.telegram.messages) == sent and len(photos(det)) == 1
    edit = det.telegram.payloads("editMessageMedia")[-1]
    media = json.loads(edit["media"])
    assert edit["message_id"] == 55 and media["type"] == "photo" and media["media"] == "attach://card"
    assert BLOCKED in media["caption"] and media["caption_entities"] == ENTITIES and "parse_mode" not in media
    assert sent_files(det, "editMessageMedia")[0]["card"][1].startswith(b"\x89PNG")
    assert sent_files(det, "editMessageMedia")[0]["card"][1] != sent_files(det, "sendPhoto")[0]["photo"][1]
    assert "↩️ Undo block" in labels(edit) and "🔕 Mute 24 h" in labels(edit)


def test_undoing_a_block_redraws_the_card_again(make_detector):
    bot, det, api = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    press_on_photo(bot, photos(det)[0], "Block")
    first = det.telegram.payloads("editMessageMedia")[-1]
    blocked = {**first, "caption": json.loads(first["media"])["caption"]}
    press_on_photo(bot, blocked, "Undo block")
    assert api.calls[-1][0] == "delete_domain"
    edit = det.telegram.payloads("editMessageMedia")[-1]
    assert "Unblocked evil-c2.example" in json.loads(edit["media"])["caption"]
    assert "🛡 Block evil-c2.example" in labels(edit)
    drawn = [files["card"][1] for files in sent_files(det, "editMessageMedia")]
    assert drawn[0] != drawn[1]


def test_mute_changes_only_the_caption(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    press_on_photo(bot, photos(det)[0], "Mute 7 d")
    assert det.telegram.payloads("editMessageMedia") == []
    edit = det.telegram.payloads("editMessageCaption")[-1]
    assert "🔕 Muted" in edit["caption"] and edit["caption_entities"] == ENTITIES
    assert "🔔 Undo mute" in labels(edit)


def test_a_failed_redraw_still_tells_the_owner(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))
    failing(det, "editMessageMedia")
    press_on_photo(bot, photos(det)[0], "Block")
    assert BLOCKED in det.telegram.messages[-1]


def test_a_card_that_cannot_be_redrawn_still_updates_the_caption(make_detector, monkeypatch):
    bot, det, _ = setup(make_detector)
    det.process_query(q("beacon.evil-c2.example"))

    def broken(*args, **kwargs):
        raise OSError("font missing")

    monkeypatch.setattr(drawing, "alert_card", broken)
    press_on_photo(bot, photos(det)[0], "Block")
    assert BLOCKED in det.telegram.payloads("editMessageCaption")[-1]["caption"]


# --- the digest and /status -----------------------------------------------------------------------

def test_a_busy_digest_is_a_picture_with_its_buttons(make_detector):
    bot, det, _ = setup(make_detector)
    det.process_query(q("www.xk7qz9w2vb4m.com"))
    det.state.put("last_digest", T0 - DAY)
    assert det.maybe_digest(T0 + 60, force=True)
    photo = photos(det)[-1]
    assert "🛡 Block xk7qz9w2vb4m.com" in labels(photo) and "📄 Full report" in labels(photo)
    assert "Random-looking domain" in photo["caption"] and "lookup checked" in photo["caption"]


def test_a_digest_keeps_low_alerts_in_its_caption(make_detector):
    from pihole_detector.sinks import digest_caption
    low = {"severity": "LOW", "rule": "device_silent", "label": "iPad", "evidence": {"hours": 26}, "time": T0}
    assert "iPad" in digest_caption([low], {"queries": 5}, T0, T0 + DAY)


def test_a_huge_digest_caption_stays_within_the_limit():
    from pihole_detector.sinks import digest_caption
    records = [{"severity": "MEDIUM", "rule": f"rule{i}", "label": "x" * 80, "domain": "y" * 80, "time": T0}
               for i in range(60)]
    caption = digest_caption(records, {"queries": 5}, T0, T0 + DAY)
    assert len(caption) <= 1024 and caption.count("<blockquote") == caption.count("</blockquote>")


def test_a_quiet_digest_stays_one_line_of_text(make_detector):
    _, det, _ = setup(make_detector)
    det.state.put("last_digest", T0 - DAY)
    det.maybe_digest(T0, force=True)
    assert photos(det) == [] and det.telegram.messages[-1].startswith("✅ <b>Digest: nothing suspicious")


def test_a_digest_picture_that_fails_still_counts_as_sent_as_text(make_detector):
    _, det, _ = setup(make_detector)
    det.process_query(q("www.xk7qz9w2vb4m.com"))
    det.state.put("last_digest", T0 - DAY)
    failing(det, "sendPhoto")
    det.maybe_digest(T0 + 60, force=True)
    assert "Digest:" in det.telegram.messages[-1] and det.state.get("last_digest") == T0 + 60


def test_status_is_a_picture(make_detector):
    bot, det, _ = setup(make_detector)
    bot.handle(message("/status"), T0)
    assert sent_files(det, "sendPhoto") and "Instant alerts" in photos(det)[-1]["caption"]


def test_status_with_pihole_down_still_answers(make_detector):
    bot, det, api = setup(make_detector)
    api.down = True
    bot.handle(message("/status"), T0)
    assert photos(det) and "Pi-hole: ApiError" in photos(det)[-1]["caption"]


def test_status_text_is_still_there_when_pictures_fail(make_detector):
    bot, det, _ = setup(make_detector)
    failing(det, "sendPhoto")
    bot.handle(message("/status"), T0)
    assert det.telegram.messages[-1].startswith("✅ <b>Status: Pi-hole is up and blocking</b>")
