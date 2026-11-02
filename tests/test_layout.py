"""Every message reads the same way: what happened, what matters, what you can do, the technical rest folded."""

import re

import pytest

from pihole_detector.bot import Bot
from pihole_detector.model import Client, Device
from pihole_detector.sinks import format_down, format_up, layout
from conftest import PC_IP, PC_MAC, T0, FakePihole, q

OWNER = 42
FOLD = re.compile(r"<blockquote expandable>(.*?)</blockquote>", re.S)


def visible(text):
    return FOLD.sub("", text)


def folded(text):
    return FOLD.search(text).group(1)


def message(text, date=T0):
    return {"update_id": 1, "message": {"message_id": 100, "date": int(date), "text": text,
                                        "chat": {"id": OWNER, "type": "private"}, "from": {"id": OWNER}}}


def make_bot(make_detector, api=None):
    api = api or FakePihole(
        devices=[Device(hwaddr=PC_MAC, ips=(PC_IP,), first_seen=T0 - 86400, last_query=T0 - 120, vendor="Acme")],
        clients=[Client(mac=PC_MAC, client=PC_MAC.upper(), comment="AswinPC", groups=(0, 1))])
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, api=api, push_enabled=True, dedup_hours=0)
    det.intel.names[PC_MAC] = "AswinPC"
    return Bot(det, api, det.telegram, started=T0 - 3600), det, api


def reply(bot, det, text):
    bot.handle(message(text), T0)
    return det.telegram.messages[-1]


# --- the layout itself ---------------------------------------------------------------------

def test_the_parts_come_in_one_order():
    assert layout("🔴", "Headline", ["fact one", "fact two"], "What to do", ["tech"]) == (
        "🔴 <b>Headline</b>\nfact one\nfact two\n\nWhat to do\n\n<blockquote expandable>tech</blockquote>")


def test_parts_a_message_does_not_need_leave_no_gaps():
    assert layout("✅", "Done") == "✅ <b>Done</b>"
    assert layout("✅", "Done", details=["tech"]) == "✅ <b>Done</b>\n\n<blockquote expandable>tech</blockquote>"


def test_empty_details_are_left_out():
    assert folded(layout("✅", "Done", details=["a", "", None, "b"])) == "a\nb"


def test_a_message_too_long_for_telegram_loses_facts_but_stays_valid():
    text = layout("📊", "Report", [f"<b>line {i}</b>" for i in range(2000)], "Act", ["tech"])
    assert len(text) <= 4000
    assert "… cut short" in text and "Act" in text and folded(text) == "tech"
    assert text.count("<b>") == text.count("</b>")


# --- health ---------------------------------------------------------------------------------

def test_an_outage_says_what_it_means_and_what_to_do():
    text = format_down(3, "connection refused")
    assert text.startswith("🚨 <b>Pi-hole is not responding</b>\n")
    assert "no device can open websites" in visible(text)
    assert "Check the Pi-hole container" in visible(text)
    assert "connection refused" in folded(text)


def test_recovery_is_one_short_message():
    assert format_up(75) == "✅ <b>Pi-hole is back</b>\nReachable again after 1 min 15 s."


# --- /status --------------------------------------------------------------------------------

def test_status_leads_with_the_answer(make_detector):
    bot, det, _ = make_bot(make_detector)
    text = reply(bot, det, "/status")
    assert text.startswith("✅ <b>Status: Pi-hole is up and blocking</b>\n")
    assert "1 h" in folded(text) and "Rotation sync" in folded(text)


def test_status_leads_with_trouble(make_detector):
    bot, det, api = make_bot(make_detector)
    api.down = True
    assert reply(bot, det, "/status").startswith("🚨 <b>Status: Pi-hole is not reachable</b>\n")


def test_status_says_when_blocking_is_paused_and_how_to_resume(make_detector):
    bot, det, api = make_bot(make_detector)
    api.get = lambda path, params=None: {"blocking": "disabled", "timer": 120}
    text = reply(bot, det, "/status")
    assert text.startswith("⚠️ <b>Status: blocking is disabled, back on in 2 min</b>\n")
    assert "/resume" in visible(text)


def test_status_keeps_holds_and_failed_polls_in_view(make_detector):
    bot, det, _ = make_bot(make_detector)
    det.stats["api_failures"] = 2
    reply(bot, det, "/mute 1h")
    text = reply(bot, det, "/status")
    assert "2 failed polls" in visible(text) and "Muted until" in visible(text) and "/unmute" in visible(text)


# --- /whois ---------------------------------------------------------------------------------

def test_whois_leads_with_what_the_device_is_doing(make_detector):
    bot, det, _ = make_bot(make_detector)
    text = reply(bot, det, f"/whois {PC_IP}")
    assert text.startswith("🔎 <b>AswinPC</b>\n")
    assert "Last lookup 2 min ago" in visible(text) and "Groups: Default, Aswin" in visible(text)


def test_whois_keeps_recent_alerts_in_view_and_addresses_folded(make_detector):
    bot, det, api = make_bot(make_detector)
    det.process_devices(api.devices_, T0)
    det.process_query(q("evil-c2.example", ip=PC_IP))
    text = reply(bot, det, f"/whois {PC_IP}")
    assert "ti_match" in visible(text)
    assert PC_MAC in folded(text) and PC_MAC not in visible(text)
    assert "First seen" in folded(text) and "Name from" in folded(text)


def test_whois_folds_top_domains(make_detector):
    bot, det, api = make_bot(make_detector)
    api.queries = [q("tracker.example", t=-60, ip=PC_IP)]
    text = reply(bot, det, f"/whois {PC_IP}")
    assert "tracker.example" in folded(text) and "tracker.example" not in visible(text)


def test_whois_points_at_what_can_be_done(make_detector):
    bot, det, _ = make_bot(make_detector)
    text = reply(bot, det, f"/whois {PC_IP}")
    assert "/name" in visible(text) and "/group" in visible(text)


def test_a_huge_whois_stays_valid(make_detector):
    bot, det, api = make_bot(make_detector)
    api.devices_ = [Device(hwaddr=PC_MAC, ips=tuple(f"192.0.2.{i}" for i in range(250)) * 30, first_seen=T0)]
    text = reply(bot, det, "/whois aswinpc")
    assert len(text) <= 4096 and text.count("<blockquote") == text.count("</blockquote>")


# --- errors ---------------------------------------------------------------------------------

@pytest.mark.parametrize("command, fail, lead", [
    ("/block tracker.example", {"add_domain": "POST: HTTP 400"}, "⚠️ <b>Pi-hole refused that</b>\nPOST: HTTP 400"),
    ("/unblock tracker.example", {"delete_domain": "DELETE: HTTP 500"}, "⚠️ <b>Pi-hole refused that</b>\nDELETE: HTTP 500"),
    ("/name aswinpc Desk", {"clients": "GET: HTTP 500"}, "🚨 <b>Couldn't ask Pi-hole</b>\nGET: HTTP 500"),
])
def test_an_error_says_what_failed_then_where_to_look(make_detector, command, fail, lead):
    bot, det, api = make_bot(make_detector)
    api.fail = fail
    text = reply(bot, det, command)
    assert text.startswith(lead) and "/status" in text


def test_a_failed_device_lookup_reads_the_same_way(make_detector):
    bot, det, api = make_bot(make_detector)
    api.down = True
    text = reply(bot, det, "/devices")
    assert text.startswith("🚨 <b>Couldn't ask Pi-hole for its devices</b>\n") and "ApiError" in text


def test_a_stale_command_says_what_happened_then_what_to_do(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(message("/pause", date=T0 - 600), T0)
    assert det.telegram.messages[-1] == (
        "⌛ <b>That command is from a while ago</b>\nI didn't run it.\n\nSend it again if you still want it.")
