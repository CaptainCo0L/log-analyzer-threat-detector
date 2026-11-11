"""The owner never waits on the poll loop: a press is acknowledged at once and a reply goes out when it can."""

import queue

from pihole_detector.bot import Bot, TelegramPoller, start_bot
from pihole_detector.runner import Runner
from conftest import T0, FakePihole, press

OWNER = 42


def message(text="/help", update_id=1):
    return {"update_id": update_id, "message": {"message_id": 100, "date": int(T0), "text": text,
                                                "chat": {"id": OWNER, "type": "private"}, "from": {"id": OWNER}}}


def service(make_detector, **cfg):
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, **cfg)
    det.digests = False
    api = FakePihole()
    bot = start_bot(det, api, run=False)
    return Runner(det, api, T0, bot=bot), bot, det


def clock(*times):
    ticks = iter(times)
    return lambda: next(ticks)


def test_an_update_wakes_the_main_loop(make_detector):
    det = make_detector(telegram_chat_id=str(OWNER))
    det.telegram.updates = [[{"update_id": 10}]]
    poller = TelegramPoller(det.telegram, queue.Queue())
    assert not poller.wake.is_set()
    poller.poll_once()
    assert poller.wake.is_set()


def test_a_quiet_long_poll_wakes_nothing(make_detector):
    det = make_detector(telegram_chat_id=str(OWNER))
    poller = TelegramPoller(det.telegram, queue.Queue())
    poller.poll_once()
    assert not poller.wake.is_set()


def test_the_bot_and_its_poller_share_the_wake_signal(make_detector):
    _, bot, _ = service(make_detector)
    assert bot.poller.wake is bot.wake


def test_waiting_for_the_next_poll_answers_an_update_straight_away(make_detector):
    runner, bot, det = service(make_detector)
    bot.inbox.put(message())
    bot.wake.set()
    runner.idle(3.0, clock=clock(0.0, 0.0, 9.0))  # no sleeping: the wake is already set
    assert any("/whois" in text for text in det.telegram.messages)
    assert det.state.get("bot_offset") == 2


def test_it_goes_back_to_waiting_after_answering(make_detector):
    runner, bot, det = service(make_detector)
    bot.inbox.put(message())
    bot.wake.set()
    runner.idle(0.01, clock=clock(0.0, 0.0, 0.0, 9.0))
    assert not bot.wake.is_set()


def test_an_answered_update_is_saved_at_once(make_detector, tmp_path):
    from pihole_detector.state import State
    runner, bot, det = service(make_detector)
    path = tmp_path / "state.db"
    det.state = bot.det.state = State(path)
    bot.inbox.put(message(update_id=7))
    bot.wake.set()
    runner.idle(3.0, clock=clock(0.0, 0.0, 9.0))
    assert State(path).get("bot_offset") == 8


def test_without_a_bot_it_just_sleeps(make_detector, monkeypatch):
    import time
    slept = []
    monkeypatch.setattr(time, "sleep", slept.append)
    det = make_detector()
    Runner(det, FakePihole(), T0).idle(3.0)
    assert slept == [3.0]


def order_of(det, *methods):
    return [m for m, _, _ in det.telegram.calls if m in methods]


def test_a_press_is_acknowledged_before_pihole_is_asked(make_detector):
    api = FakePihole()
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, api=api)
    bot = Bot(det, api, det.telegram, started=T0)
    seen_at_write = []
    real = api.add_domain

    def add_domain(*args, **kwargs):
        seen_at_write.extend(order_of(det, "answerCallbackQuery"))
        real(*args, **kwargs)

    api.add_domain = add_domain
    data = det.actions.block("evil.example", T0)["callback_data"]
    bot.handle(press(data), T0)
    assert seen_at_write == ["answerCallbackQuery"]
    assert det.telegram.payloads("answerCallbackQuery")[0]["text"] == "Blocking…"


def test_every_press_is_answered_exactly_once(make_detector):
    api = FakePihole(fail={"add_domain": "POST: HTTP 400"})
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True, api=api)
    bot = Bot(det, api, det.telegram, started=T0)
    data = det.actions.block("evil.example", T0)["callback_data"]
    bot.handle(press(data), T0)
    assert len(det.telegram.payloads("answerCallbackQuery")) == 1
    assert "HTTP 400" in det.telegram.messages[-1]

