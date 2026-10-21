"""Baseline: how familiar a client -> apex relationship is, the one question several rules share."""

from pihole_detector.baseline import KNOWN, LEARNING, NEW, Baseline
from pihole_detector.config import Config
from pihole_detector.state import State

DAY = 86400


def make(learning_days=7, shared_clients=3):
    state = State(":memory:")
    return state, Baseline(state, Config(learning_days=learning_days, shared_clients=shared_clients))


def seen(state, ident, apex, t):
    state.touch_client(ident, t)
    state.remember_domain(ident, apex, t)


def test_everything_is_learning_while_the_client_is_young():
    state, base = make()
    seen(state, "c", "a.example", 0)
    seen(state, "c", "b.example", 6 * DAY)
    assert base.familiarity("c", "a.example", 6 * DAY).stage == LEARNING
    assert base.familiarity("c", "b.example", 6 * DAY).stage == LEARNING


def test_apex_learned_during_the_learning_week_stays_known():
    # The cold start seen live: an hourly IoT heartbeat learned on day 0 must not read as new on day 8.
    state, base = make()
    seen(state, "c", "vendor.example", 0)
    seen(state, "c", "late.example", 6 * DAY)   # learned on the last day of the week
    assert base.familiarity("c", "vendor.example", 8 * DAY).stage == KNOWN
    assert base.familiarity("c", "late.example", 8 * DAY).stage == KNOWN


def test_apex_first_seen_after_learning_is_new_until_it_is_a_week_old():
    state, base = make()
    seen(state, "c", "a.example", 0)
    seen(state, "c", "fresh.example", 10 * DAY)
    assert base.familiarity("c", "fresh.example", 10 * DAY).stage == NEW
    assert base.familiarity("c", "fresh.example", 16 * DAY).stage == NEW
    assert base.familiarity("c", "fresh.example", 17 * DAY).stage == KNOWN


def test_shared_when_enough_clients_use_the_apex():
    state, base = make(shared_clients=3)
    for ident in ("a", "b"):
        seen(state, ident, "cdn.example", 0)
    assert not base.familiarity("a", "cdn.example", 0).shared
    seen(state, "c", "cdn.example", 0)
    assert base.familiarity("a", "cdn.example", 0).shared


def test_unknown_client_and_apex_count_as_learning_not_shared():
    _, base = make()
    fam = base.familiarity("nobody", "x.example", 0)
    assert fam.stage == LEARNING and not fam.shared
