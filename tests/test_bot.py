"""The two-way bot: auth, the update loop, one-shot buttons and the read commands (stage 1)."""

import queue

from pihole_detector.bot import BOT_COMMANDS, Bot, TelegramPoller, drain
from pihole_detector.model import Alert, Device, Query
from pihole_detector.rotation import Client
from pihole_detector.state import State
from conftest import IOT_IP, IOT_MAC, PC_IP, PC_MAC, T0, FakePihole

OWNER = 42
DAY = 86400


def message(text, chat=OWNER, sender=OWNER, date=T0, update_id=1):
    return {"update_id": update_id, "message": {"message_id": 100, "date": int(date), "text": text,
                                                "chat": {"id": chat, "type": "private"}, "from": {"id": sender}}}


def press(data, chat=OWNER, sender=OWNER, update_id=2, message_date=T0):
    return {"update_id": update_id, "callback_query": {
        "id": "cb1", "from": {"id": sender}, "data": data,
        "message": {"message_id": 55, "date": int(message_date), "chat": {"id": chat, "type": "private"}}}}


def make_bot(make_detector, api=None, now=T0):
    det = make_detector(telegram_chat_id=str(OWNER))
    api = api or FakePihole(devices=[Device(hwaddr=PC_MAC, ips=(PC_IP,), first_seen=T0 - 9 * DAY,
                                            last_query=now - 60, vendor="Acme", name="pc.lan"),
                                     Device(hwaddr=IOT_MAC, ips=(IOT_IP,), first_seen=T0 - 30 * DAY,
                                            last_query=now - 2 * DAY, vendor="LG")],
                            clients=[Client(mac=PC_MAC, client=PC_MAC.upper(), comment="AswinPC", groups=(0, 1))])
    det.intel.names[PC_MAC] = "AswinPC"
    return Bot(det, api, det.telegram, started=now - 3600), det, api


def replies(det):
    return det.telegram.messages


# --- auth -----------------------------------------------------------------------------------

def test_only_the_owner_in_their_private_chat_is_answered(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(message("/status", chat=7, sender=7), T0)
    bot.handle(message("/status", chat=OWNER, sender=7), T0)   # someone else, same chat id (a group)
    bot.handle(press("a:x", chat=7, sender=7), T0)
    assert det.telegram.calls == []
    bot.handle(message("/status"), T0)
    assert len(replies(det)) == 1


def test_unknown_commands_and_plain_text_get_the_help(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(message("hello"), T0)
    bot.handle(message("/nope"), T0)
    assert all("/status" in r and "/whois" in r for r in replies(det))


def test_a_command_addressed_to_the_bot_by_name_still_works(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(message("/status@aswin_pihole_alert_bot"), T0)
    assert "Pi-hole" in replies(det)[0]


# --- the update loop ------------------------------------------------------------------------

def test_poller_queues_updates_and_moves_the_offset_past_them(make_detector):
    bot, det, _ = make_bot(make_detector)
    det.telegram.updates = [[{"update_id": 10}, {"update_id": 11}]]
    inbox = queue.Queue()
    poller = TelegramPoller(det.telegram, inbox, offset=10)
    poller.poll_once()
    assert [inbox.get_nowait()["update_id"] for _ in range(2)] == [10, 11]
    assert poller.offset == 12
    assert det.telegram.payloads("getUpdates")[0]["offset"] == 10


def test_drain_handles_each_update_and_remembers_the_offset(make_detector):
    bot, det, _ = make_bot(make_detector)
    inbox = queue.Queue()
    inbox.put(message("/status", update_id=20))
    inbox.put(message("/devices", update_id=21))
    drain(inbox, bot, det.state, T0)
    assert len(replies(det)) == 2 and det.state.get("bot_offset") == 22


def test_one_bad_update_does_not_stop_the_rest(make_detector):
    bot, det, _ = make_bot(make_detector)
    inbox = queue.Queue()
    inbox.put({"update_id": 30, "message": "not a dict"})
    inbox.put(message("/status", update_id=31))
    drain(inbox, bot, det.state, T0)
    assert len(replies(det)) == 1 and det.state.get("bot_offset") == 32


def test_every_command_is_in_the_menu_with_a_valid_name():
    import re
    assert {"status", "report", "devices", "whois", "help"} <= {c for c, _ in BOT_COMMANDS}
    assert all(re.fullmatch(r"[a-z0-9_]{1,32}", c) and 1 <= len(d) <= 256 for c, d in BOT_COMMANDS)


# --- one-shot buttons -----------------------------------------------------------------------

def test_a_button_works_once():
    state = State()
    aid = state.add_action({"kind": "x"}, T0)
    assert len(f"a:{aid}".encode()) <= 64  # Telegram's callback_data limit
    assert state.take_action(aid, T0 + 10) == {"kind": "x"}
    assert state.take_action(aid, T0 + 11) is None


def test_a_button_expires_after_a_day():
    state = State()
    aid = state.add_action({"kind": "x"}, T0)
    assert state.take_action(aid, T0 + DAY + 1) is None
    old = state.add_action({"kind": "y"}, T0)
    state.prune(T0 + DAY + 1)
    assert state.db.execute("SELECT count(*) FROM action").fetchone()[0] == 0 and old


def test_an_expired_button_says_so_and_stops_the_spinner(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(press("a:gone"), T0)
    answer = det.telegram.payloads("answerCallbackQuery")[0]
    assert answer["callback_query_id"] == "cb1" and "expired" in answer["text"]


# --- /status --------------------------------------------------------------------------------

def test_status_shows_pihole_health_and_activity(make_detector):
    bot, det, _ = make_bot(make_detector)
    det.stats.update({"queries": 1234, "alert_HIGH": 2})
    bot.handle(message("/status"), T0)
    text = replies(det)[0]
    assert "Pi-hole" in text and "enabled" in text and "1,234" in text and "2 high" in text.lower()
    assert "1 h" in text  # detector uptime


def test_status_reports_pihole_unreachable(make_detector):
    bot, det, api = make_bot(make_detector)
    api.down = True
    bot.handle(message("/status"), T0)
    assert "not reachable" in replies(det)[0]


# --- /report --------------------------------------------------------------------------------

def alert(t, severity="HIGH", rule="ti_match", client="AswinPC", domain="evil-c2.example"):
    return Alert(time=t, severity=severity, rule=rule, client=client, domain=domain, message="m",
                 address=f"{PC_IP} · {PC_MAC}", dedup=f"{rule}|{t}")


def test_report_summarises_and_offers_the_full_report(make_detector):
    bot, det, _ = make_bot(make_detector)
    for i in range(3):
        det.alert_log.write(alert(T0 - i * 3600))
    det.alert_log.write(alert(T0 - 3600, "MEDIUM", "beaconing", domain="tick.example"))
    det.alert_log.write(alert(T0 - 10 * DAY))  # outside the window
    bot.handle(message("/report 7"), T0)
    text = replies(det)[0]
    assert "3 high" in text.lower() and "1 medium" in text.lower() and "<blockquote expandable>" in text
    button = det.telegram.payloads()[0]["reply_markup"]["inline_keyboard"][0][0]
    assert "Full report" in button["text"] and button["callback_data"].startswith("a:")
    bot.handle(press(button["callback_data"]), T0 + 5)
    sent = [c for c in det.telegram.calls if c[0] == "sendDocument"][0]
    filename, content = sent[2]["document"]
    assert filename.endswith(".md") and b"# Pi-hole detector review" in content and b"evil-c2.example" in content
    assert det.telegram.calls[-1][0] == "answerCallbackQuery"  # the spinner stops after the work


def test_report_days_are_bounded_and_default_to_seven(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(message("/report"), T0)
    bot.handle(message("/report 999"), T0)
    bot.handle(message("/report abc"), T0)
    texts = replies(det)
    assert "7 days" in texts[0] and "30 days" in texts[1] and "7 days" in texts[2]


def test_a_huge_report_still_fits_one_message(make_detector):
    bot, det, _ = make_bot(make_detector)
    for i in range(400):
        det.alert_log.write(alert(T0 - i * 60, domain=f"d{i}-{'x' * 40}.example", client=f"device-{i}"))
    bot.handle(message("/report 1"), T0)
    assert len(replies(det)[0]) <= 4096


# --- /devices -------------------------------------------------------------------------------

def test_devices_lists_who_is_online_with_name_ip_and_groups(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(message("/devices"), T0)
    text = replies(det)[0]
    assert "AswinPC" in text and PC_IP in text and "Default, Aswin" in text
    assert "LG" not in text and "1 offline" in text and "/devices all" in text
    bot.handle(message("/devices all"), T0)
    assert "LG" in replies(det)[1] or IOT_IP in replies(det)[1]


# --- /whois ---------------------------------------------------------------------------------

def pc_queries(n_tracker=5, n_other=2):
    rows = [Query(id=i, time=T0 - 100 - i, domain=f"x{i}.tracker.example", type="A", status="FORWARDED",
                  reply="IP", client_ip=PC_IP) for i in range(n_tracker)]
    rows += [Query(id=99 + i, time=T0 - 50, domain="www.news.example", type="A", status="FORWARDED",
                   reply="IP", client_ip=PC_IP) for i in range(n_other)]
    rows.append(Query(id=500, time=T0 - 10, domain="secret.other.example", type="A", status="FORWARDED",
                      reply="IP", client_ip=IOT_IP))
    return rows


def test_whois_finds_a_device_by_name_ip_or_mac(make_detector):
    bot, det, api = make_bot(make_detector)
    api.queries = pc_queries()
    for query in ("aswinpc", PC_IP, PC_MAC.upper()):
        bot.handle(message(f"/whois {query}"), T0)
    for text in replies(det):
        assert "AswinPC" in text and PC_MAC in text and "Clients comment" in text and "Default, Aswin" in text


def test_whois_shows_top_domains_for_that_device_only_and_recent_alerts(make_detector):
    bot, det, api = make_bot(make_detector)
    api.queries = pc_queries()
    for i in range(7):
        det.alert_log.write(alert(T0 - i * 60, domain=f"a{i}.example"))
    bot.handle(message(f"/whois {PC_IP}"), T0)
    text = replies(det)[0]
    assert text.index("tracker.example") < text.index("news.example")  # most queried first
    assert "other.example" not in text
    assert api.query_calls[0] == (T0 - DAY, {"client_ip": PC_IP})
    assert text.count("ti_match") == 5  # the last five alerts only


def test_whois_with_no_match_or_several_matches_says_so(make_detector):
    bot, det, _ = make_bot(make_detector)
    bot.handle(message("/whois toaster"), T0)
    bot.handle(message("/whois"), T0)
    assert "No device" in replies(det)[0] and "/whois" in replies(det)[1]


# --- wiring into the service ------------------------------------------------------------------

from pihole_detector.bot import start_bot


def test_start_bot_clears_any_webhook_registers_the_menu_and_resumes_the_offset(make_detector):
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True)
    det.state.put("bot_offset", 77)
    bot, inbox, poller = start_bot(det, FakePihole(), run=False)
    methods = [m for m, _, _ in det.telegram.calls]
    assert methods[:2] == ["deleteWebhook", "setMyCommands"] and poller.offset == 77


def test_bot_is_off_unless_enabled(make_detector):
    det = make_detector(telegram_chat_id=str(OWNER))
    assert start_bot(det, FakePihole(), run=False) is None and det.telegram.calls == []


# --- /whois name matching (live 2026-10-27: "/whois Aswins ipad" found nothing) ----------------

IPAD_A, IPAD_B = "06:da:8f:c5:97:97", "4e:09:bc:48:0a:47"


def ipad_bot(make_detector, extra=()):
    devices = [Device(hwaddr=IPAD_A, ips=("192.0.2.86",), first_seen=T0 - 3 * DAY, last_query=T0 - 3600),
               Device(hwaddr=IPAD_B, ips=("192.0.2.87",), first_seen=T0 - DAY, last_query=T0 - 30), *extra]
    bot, det, api = make_bot(make_detector, api=FakePihole(devices=devices))
    det.intel.names[IPAD_A] = det.intel.names[IPAD_B] = "Aswins-iPad"
    return bot, det


def test_whois_ignores_case_spaces_hyphens_and_apostrophes(make_detector):
    bot, det = ipad_bot(make_detector)
    for query in ("Aswins ipad", "aswin's iPad", "ASWINS-IPAD", "aswinsipad"):
        bot.handle(message(f"/whois {query}"), T0)
    assert all("Aswins-iPad" in r and "No device" not in r for r in replies(det))


def test_whois_shows_the_newest_mac_of_a_device_and_lists_its_others(make_detector):
    bot, det = ipad_bot(make_detector)
    bot.handle(message("/whois Aswins ipad"), T0)
    text = replies(det)[0]
    assert f"MAC <code>{IPAD_B}</code>" in text           # the one used most recently
    assert "Also seen as" in text and IPAD_A in text and "Several" not in text


def test_whois_matches_part_of_a_name_and_any_name_a_device_has(make_detector):
    tablet = Device(hwaddr="0a:00:00:00:00:77", ips=("192.0.2.77",), first_seen=T0, last_query=T0,
                    name="kitchen-tablet.lan")
    bot, det = ipad_bot(make_detector, extra=[tablet])
    det.intel.names[tablet.hwaddr] = "Kitchen"
    det.names.update({tablet.hwaddr: ("Galaxy Tab A", "mDNS")}, T0)
    for query in ("ipad", "kitchen tablet", "galaxy tab"):  # part of a name, the hostname, the discovered name
        bot.handle(message(f"/whois {query}"), T0)
    texts = replies(det)
    assert f"MAC <code>{IPAD_B}</code>" in texts[0]
    assert all("0a:00:00:00:00:77" in t and "Kitchen" in t for t in texts[1:])


def test_whois_still_asks_when_different_devices_match(make_detector):
    other = Device(hwaddr="0a:00:00:00:00:99", ips=("192.0.2.99",), first_seen=T0, last_query=T0)
    bot, det = ipad_bot(make_detector, extra=[other])
    det.intel.names[other.hwaddr] = "Dads iPad"
    bot.handle(message("/whois ipad"), T0)
    text = replies(det)[0]
    assert "Several devices match" in text and "Dads iPad" in text and "Aswins-iPad" in text


def test_an_exact_name_beats_a_partial_one(make_detector):
    other = Device(hwaddr="0a:00:00:00:00:99", ips=("192.0.2.99",), first_seen=T0, last_query=T0)
    bot, det = ipad_bot(make_detector, extra=[other])
    det.intel.names[other.hwaddr] = "Aswins-iPad mini"
    bot.handle(message("/whois aswins ipad"), T0)
    assert f"MAC <code>{IPAD_B}</code>" in replies(det)[0]
