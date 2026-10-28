"""Stage 4: alert settings from chat - mute, quiet hours, push on/off, /set and the held-alert summary."""

import time

from pihole_detector.bot import Bot
from pihole_detector.delivery import in_quiet
from pihole_detector.config import Config, Settings
from pihole_detector.state import State
from conftest import T0, q

OWNER = 42
HOUR = 3600


def message(text, date=None, update_id=1):
    return {"update_id": update_id, "message": {"message_id": 100, "date": int(date or T0), "text": text,
                                                "chat": {"id": OWNER, "type": "private"}, "from": {"id": OWNER}}}


def press(data, update_id=2):
    return {"update_id": update_id, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": data,
        "message": {"message_id": 55, "date": int(T0), "chat": {"id": OWNER, "type": "private"}}}}


def setup(make_detector, **cfg):
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, push_enabled=True, dedup_hours=0, **cfg)
    return Bot(det, None, det.telegram, started=T0), det


def local(hour, minute=0):
    """A timestamp on T0's day at hour:minute local time."""
    lt = time.localtime(T0)
    return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, hour, minute, 0, 0, 0, -1))


def pushes(det):
    return [m for m in det.telegram.messages if "Malware" in m and "While" not in m]  # not the summary


# --- /mute ---------------------------------------------------------------------------------

def test_mute_holds_high_alerts_then_sends_one_summary_when_it_ends(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/mute 1h"), T0)
    det.process_query(q("evil-c2.example", t=10))
    det.process_query(q("beacon.evil-c2.example", t=20))
    assert pushes(det) == []
    assert len(det.alert_log.read()) == 2                 # still logged
    det.tick(T0 + 30 * 60)
    assert not any("While" in m for m in det.telegram.messages)
    det.tick(T0 + HOUR + 1)
    summary = det.telegram.payloads()[-1]
    assert "2 alerts" in summary["text"] and "evil-c2.example" in summary["text"]
    blocks = [b["text"] for row in summary["reply_markup"]["inline_keyboard"] for b in row]
    assert blocks == ["🛡 Block evil-c2.example"]      # one button per domain, not per alert
    det.tick(T0 + HOUR + 60)
    assert sum("While" in m for m in det.telegram.messages) == 1  # sent once


def test_unmute_ends_it_early_and_the_summary_follows(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/mute 8h"), T0)
    det.process_query(q("evil-c2.example", t=10))
    bot.handle(message("/unmute", date=T0 + 60), T0 + 60)
    det.tick(T0 + 61)
    assert any("While you were muted" in m for m in det.telegram.messages)
    det.process_query(q("evil-c2.example", t=120))
    assert len(pushes(det)) == 1


def test_mute_durations_default_to_an_hour_and_cap_at_a_week(make_detector):
    bot, det = setup(make_detector)
    for text, expected in (("/mute", HOUR), ("/mute 30m", 1800), ("/mute 2d", 2 * 86400),
                           ("/mute 30d", 7 * 86400), ("/mute soon", HOUR)):
        bot.handle(message(text), T0)
        assert det.state.get("bot:mute_until") == T0 + expected, text


def test_health_and_rotation_messages_are_never_held(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/mute 1d"), T0)
    sent = len(det.telegram.messages)
    det.delivery.send("🚨 Pi-hole is not responding")  # how cmd_run sends health
    assert len(det.telegram.messages) == sent + 1


# --- /quiet --------------------------------------------------------------------------------

def test_quiet_hours_cross_midnight():
    assert in_quiet("23:00-07:00", local(23, 30)) and in_quiet("23:00-07:00", local(6, 59))
    assert not in_quiet("23:00-07:00", local(7, 0)) and not in_quiet("23:00-07:00", local(12))
    assert in_quiet("13:00-14:00", local(13, 30)) and not in_quiet(None, local(13, 30))


def test_quiet_hours_hold_alerts_until_they_end(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/quiet 23:00-07:00", date=local(22)), local(22))
    det.process_query(q("evil-c2.example", t=local(23, 30) - T0))
    assert pushes(det) == []
    det.tick(local(23, 59))
    det.tick(local(23, 59) + 8 * HOUR)  # 07:59 next day
    assert any("While it was quiet" in m and "1 alert" in m for m in det.telegram.messages)


def test_quiet_rejects_nonsense_and_can_be_turned_off(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/quiet 25:00-07:00"), T0)
    assert "Usage" in det.telegram.messages[-1] and det.state.get("bot:quiet") is None
    bot.handle(message("/quiet 22:30-06:15"), T0)
    assert det.state.get("bot:quiet") == "22:30-06:15"
    bot.handle(message("/quiet off"), T0)
    assert det.state.get("bot:quiet") is None


# --- /push and /set ------------------------------------------------------------------------

def test_push_off_stops_instant_alerts_and_survives_a_restart(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/push off"), T0)
    det.process_query(q("evil-c2.example", t=5))
    assert pushes(det) == [] and det.cfg.push_enabled is False
    fresh = Config(push_enabled=True)
    Settings(fresh, det.state)
    assert fresh.push_enabled is False
    bot.handle(message("/push on"), T0)
    assert det.cfg.push_enabled is True


def test_set_changes_a_threshold_live_and_unset_goes_back_to_the_env_value(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/set nxdomain_threshold 35"), T0)
    assert det.cfg.nxdomain_threshold == 35 and "35" in det.telegram.messages[-1]
    bot.handle(message("/set PUSH_CAP_PER_HOUR 5"), T0)
    assert det.cfg.push_cap_per_hour == 5  # the cap is read live: nothing keeps a copy
    bot.handle(message("/unset NXDOMAIN_THRESHOLD"), T0)
    assert det.cfg.nxdomain_threshold == Config().nxdomain_threshold


def test_set_refuses_names_off_the_list_and_bad_values(make_detector):
    bot, det = setup(make_detector)
    before = det.cfg.nxdomain_threshold
    for text in ("/set TELEGRAM_TOKEN abc", "/set STATE_DB /tmp/x", "/set NXDOMAIN_THRESHOLD lots",
                 "/set NXDOMAIN_THRESHOLD -3", "/set DIGEST_HOUR 24", "/set ROTATION_KEEP 0", "/set"):
        bot.handle(message(text), T0)
    assert det.cfg.nxdomain_threshold == before and det.cfg.digest_hour == Config().digest_hour
    assert all(("can't" in m or "Usage" in m or "must" in m) for m in det.telegram.messages)
    assert det.state.get("setting:TELEGRAM_TOKEN") is None


def test_bool_and_list_settings_parse_like_the_env_file(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/set ROTATION_SYNC true"), T0)
    bot.handle(message("/set NMAP_EXCLUDE 192.168.18.178, 192.168.18.139"), T0)
    assert det.cfg.rotation_sync is True and det.cfg.nmap_exclude == ("192.168.18.178", "192.168.18.139")


def test_settings_lists_values_and_marks_the_ones_set_from_chat(make_detector):
    bot, det = setup(make_detector)
    bot.handle(message("/set BEACON_MIN_HITS 12"), T0)
    bot.handle(message("/settings"), T0)
    text = det.telegram.messages[-1]
    assert "BEACON_MIN_HITS" in text and "12" in text and "set here" in text and "TELEGRAM_TOKEN" not in text


def test_overrides_are_applied_on_start():
    state = State()
    state.put("setting:NXDOMAIN_THRESHOLD", "40")
    state.put("setting:TELEGRAM_TOKEN", "evil")  # never applied, even if it got into the db
    cfg = Config(telegram_token="real")
    Settings(cfg, state)
    assert cfg.nxdomain_threshold == 40 and cfg.telegram_token == "real"


# --- status, menu, stale -------------------------------------------------------------------

def test_status_shows_mute_and_quiet(make_detector):
    bot, det = setup(make_detector)
    bot.api = None
    bot.handle(message("/mute 1h"), T0)
    bot.handle(message("/quiet 23:00-07:00"), T0)
    bot.handle(message("/status"), T0)
    text = det.telegram.messages[-1]
    assert "Muted until" in text and "Quiet 23:00-07:00" in text


def test_settings_commands_are_write_commands_and_in_the_menu():
    from pihole_detector.bot import BOT_COMMANDS, WRITE_COMMANDS
    names = {"mute", "unmute", "quiet", "push", "set", "unset"}
    assert names <= WRITE_COMMANDS and (names | {"settings"}) <= {c for c, _ in BOT_COMMANDS}


def test_unset_goes_back_to_the_env_value_not_the_one_saved_before_a_restart():
    state = State()
    state.put("setting:NXDOMAIN_THRESHOLD", "40")
    cfg = Config(nxdomain_threshold=25)  # what .env said
    settings = Settings(cfg, state)
    assert cfg.nxdomain_threshold == 40 and settings.applied == ["NXDOMAIN_THRESHOLD"]
    assert settings.unset("nxdomain_threshold") == 25 and cfg.nxdomain_threshold == 25
    assert state.get("setting:NXDOMAIN_THRESHOLD") is None
