"""The digest asks for attention only when something needs it, and what needs it can be acted on from there."""

import re

from pihole_detector.bot import Bot
from pihole_detector.model import Alert
from pihole_detector.sinks import build_digest, strip_html
from conftest import T0, FakePihole

DAY = 86400
OWNER = 42
FOLD = re.compile(r"<blockquote expandable>(.*?)</blockquote>", re.S)
BLOCK = "sudo docker exec pihole pihole --wild {}"


def record(severity="MEDIUM", rule="dga_single", label="TV", domain="xk7qz9w2vb4m.com", **evidence):
    return {"severity": severity, "rule": rule, "label": label, "domain": domain, "time": T0, "evidence": evidence}


def visible(text):
    return FOLD.sub("", text)


def folded(text):
    return FOLD.search(text).group(1)


def test_a_quiet_day_is_one_line():
    assert build_digest([], {"queries": 31204}, start=T0, end=T0 + DAY) == (
        "✅ <b>Digest: nothing suspicious in 31,204 lookups</b>")


def test_one_lookup_is_singular():
    assert "in 1 lookup<" in build_digest([], {"queries": 1})


def test_failed_polls_are_not_a_quiet_day():
    text = build_digest([], {"queries": 10, "api_failures": 3}, start=T0, end=T0 + DAY)
    assert text.startswith("⚠️ <b>Digest: nothing suspicious</b>\n⚠️ 3 failed polls")


def test_high_and_medium_stay_in_view():
    text = build_digest([record("HIGH", "ti_match", domain="evil.example"), record()], {}, start=T0, end=T0 + DAY)
    assert text.startswith("📊 <b>Digest: 🔴 1 high   🟠 1 medium</b>")
    assert "evil.example" in visible(text) and "xk7qz9w2vb4m.com" in visible(text)


def test_low_alerts_fold_away():
    text = build_digest([record(), record("LOW", "device_silent", label="iPad", domain="", hours=26)], {},
                        start=T0, end=T0 + DAY)
    assert "iPad" not in visible(text) and "iPad" in folded(text) and "Device went quiet" in folded(text)


def test_a_day_of_only_low_alerts_is_one_line_and_a_fold():
    text = build_digest([record("LOW", "device_silent", label="iPad", domain="", hours=26)], {}, start=T0, end=T0 + DAY)
    assert visible(text).strip() == "📊 <b>Digest: 🟡 1 low</b>"


def test_a_long_group_shows_three_and_counts_the_rest():
    text = build_digest([record(label=f"device{i}") for i in range(7)], {}, start=T0, end=T0 + DAY)
    assert "device2" in text and "device3" not in text and "+4 more" in visible(text)


def test_bookkeeping_is_folded_on_a_busy_day():
    text = build_digest([record()], {"queries": 1234}, start=T0, end=T0 + DAY)
    assert "1,234 lookups checked" in folded(text) and "alerts.jsonl" in folded(text)


# --- buttons --------------------------------------------------------------------------------

def bot_detector(make_detector, api=None, **cfg):
    api = api or FakePihole()
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, api=api, **cfg)
    det.state.put("last_digest", T0 - DAY)
    return Bot(det, api, det.telegram, started=T0), det, api


def log_alert(det, severity="MEDIUM", domain="xk7qz9w2vb4m.com", rule="dga_single", block=True):
    evidence = {"block": BLOCK.format(domain)} if block else {}
    det.alert_log.write(Alert(time=T0 - 60, severity=severity, rule=rule, label="TV", domain=domain, message="m",
                              evidence=evidence, device="tv"))


def buttons(det):
    return [b["text"] for row in det.telegram.payloads()[-1].get("reply_markup", {}).get("inline_keyboard", []) for b in row]


def test_a_quiet_digest_has_no_buttons(make_detector):
    _, det, _ = bot_detector(make_detector)
    det.maybe_digest(T0, force=True)
    assert buttons(det) == []


def test_a_busy_digest_offers_a_block_and_the_full_report(make_detector):
    _, det, _ = bot_detector(make_detector)
    log_alert(det)
    det.maybe_digest(T0, force=True)
    assert buttons(det) == ["🛡 Block xk7qz9w2vb4m.com", "📄 Full report"]


def test_alerts_with_no_command_get_no_block_button(make_detector):
    _, det, _ = bot_detector(make_detector)
    log_alert(det, block=False)
    det.maybe_digest(T0, force=True)
    assert buttons(det) == ["📄 Full report"]


def test_low_alerts_get_no_block_button(make_detector):
    _, det, _ = bot_detector(make_detector)
    log_alert(det, severity="LOW")
    det.maybe_digest(T0, force=True)
    assert buttons(det) == ["📄 Full report"]


def test_one_domain_gets_one_button_and_high_alerts_come_first(make_detector):
    _, det, _ = bot_detector(make_detector)
    log_alert(det, domain="medium.example")
    log_alert(det, domain="medium.example")
    log_alert(det, severity="HIGH", domain="high.example", rule="ti_match")
    det.maybe_digest(T0, force=True)
    assert buttons(det) == ["🛡 Block high.example", "🛡 Block medium.example", "📄 Full report"]


def test_at_most_five_block_buttons(make_detector):
    _, det, _ = bot_detector(make_detector)
    for i in range(8):
        log_alert(det, domain=f"d{i}.example")
    det.maybe_digest(T0, force=True)
    assert len(buttons(det)) == 6


def test_without_the_bot_there_are_no_buttons(make_detector):
    det = make_detector(telegram_chat_id=str(OWNER))
    det.state.put("last_digest", T0 - DAY)
    log_alert(det)
    det.maybe_digest(T0, force=True)
    assert buttons(det) == []


def test_blocking_from_the_digest_changes_the_digest(make_detector):
    bot, det, api = bot_detector(make_detector)
    log_alert(det)
    det.maybe_digest(T0, force=True)
    sent = det.telegram.payloads()[-1]
    rows = sent["reply_markup"]["inline_keyboard"]
    count = len(det.telegram.messages)
    bot.handle({"update_id": 2, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": rows[0][0]["callback_data"],
        "message": {"message_id": 7, "date": int(T0), "chat": {"id": OWNER, "type": "private"},
                    "text": strip_html(sent["text"]), "entities": [], "reply_markup": {"inline_keyboard": rows}}}}, T0 + 5)
    assert api.calls[0][:2] == ("add_domain", "deny") and len(det.telegram.messages) == count
    edit = det.telegram.payloads("editMessageText")[-1]
    assert "Blocked xk7qz9w2vb4m.com" in edit["text"]
    labels = [b["text"] for row in edit["reply_markup"]["inline_keyboard"] for b in row]
    assert labels == ["↩️ Undo block", "📄 Full report"]
