from pihole_detector.runner import Runner
from conftest import PC_IP, T0, FakePihole, q


def setup(make_detector, **cfg):
    det = make_detector(fail_threshold=3, poll_seconds=3, **cfg)
    det.digests = False
    api = FakePihole()
    return Runner(det, api, T0), det, api


def test_each_new_query_reaches_the_detector_once(make_detector):
    runner, det, api = setup(make_detector)
    api.queries = [q("evil-c2.example", t=1, ip=PC_IP)]
    runner.poll(T0 + 10)
    runner.poll(T0 + 13)   # the same query comes back in the overlap window
    assert det.stats["queries"] == 1
    assert [r["rule"] for r in det.alert_log.read()] == ["ti_match"]


def test_three_failed_polls_push_down_once_then_up_on_recovery(make_detector):
    runner, det, api = setup(make_detector)
    api.down = True
    waits = [runner.poll(T0 + i) for i in range(5)]
    assert waits == [6, 12, 24, 30, 30]       # backs off, never past 30 s
    down = [m for m in det.telegram.messages if "not responding" in m.lower() or "unreachable" in m.lower()]
    assert len(down) == 1 and det.stats["api_failures"] == 5
    api.down = False
    assert runner.poll(T0 + 100) == 3
    assert len(det.telegram.messages) == 2     # the down notice, then the recovery
    assert runner.failures == 0 and runner.down_since is None


def test_a_short_blip_pushes_nothing(make_detector):
    runner, det, api = setup(make_detector)
    api.down = True
    runner.poll(T0)
    runner.poll(T0 + 6)
    api.down = False
    runner.poll(T0 + 18)
    assert det.telegram.messages == []


def test_health_pushes_can_be_turned_off(make_detector):
    runner, det, api = setup(make_detector, health_push_enabled=False)
    api.down = True
    for i in range(4):
        runner.poll(T0 + i)
    assert det.telegram.messages == []
