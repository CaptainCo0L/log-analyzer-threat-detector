from pihole_detector.config import Config
from pihole_detector.delivery import Delivery
from pihole_detector.model import Alert
from pihole_detector.state import State
from conftest import T0, FakeTelegram


def alert(t, severity="HIGH"):
    return Alert(time=T0 + t, severity=severity, rule="ti_match", client="PC", domain="evil.example",
                 message="m", evidence={}, dedup=f"ti_match|pc|{t}")


def delivery(**cfg):
    return Delivery(Config(push_enabled=True, **cfg), State(":memory:"), FakeTelegram())


def test_push_cap_sends_one_notice_then_recovers_after_an_hour():
    d = delivery(push_cap_per_hour=3)
    for i in range(6):
        d.route(alert(i))
    assert len(d.telegram.messages) == 4 and "Too many alerts" in d.telegram.messages[3]
    d.route(alert(3601))
    assert len(d.telegram.messages) == 5 and "Too many" not in d.telegram.messages[4]


def test_the_cap_is_read_live_so_set_takes_effect_at_once():
    d = delivery(push_cap_per_hour=1)
    d.route(alert(0))
    d.cfg.push_cap_per_hour = 5
    d.route(alert(1))
    assert not any("Too many" in m for m in d.telegram.messages) and len(d.telegram.messages) == 2


def test_send_is_never_capped_held_or_muted():
    d = delivery(push_cap_per_hour=1)
    d.route(alert(0))
    d.mute_all(T0 + 3600)
    assert d.send("health") and d.send("again")


def test_only_high_alerts_with_push_on_are_routed_to_the_phone():
    d = delivery()
    d.route(alert(0, "MEDIUM"))
    d.cfg.push_enabled = False
    d.route(alert(1))
    assert d.telegram.messages == []
