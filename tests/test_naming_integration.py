"""Discovered names flowing through the detector: alerts, silent devices, the daily report."""

import time

from pihole_detector.model import Alert
from pihole_detector.namestore import NameStore
from conftest import FakeTelegram, IOT_IP, IOT_MAC, PC_IP, PC_MAC, T0, q

MONDAY_9AM = time.mktime((2026, 10, 19, 9, 5, 0, 0, 0, -1))  # a Monday, local time
TUESDAY_9AM = MONDAY_9AM + 86400


def with_store(det, tmp_path):
    det.names = NameStore(tmp_path / "names.json")
    return det


def evil(t=0.0):
    return q("evil-c2.example", t)


def test_alert_uses_the_saved_name_when_there_is_no_clients_comment(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.names.update({PC_MAC: ("Aswins-PC", "mDNS")}, T0)
    alerts = det.process_query(evil())
    assert [a.client for a in alerts] == ["Aswins-PC"]


def test_clients_comment_beats_the_saved_name(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.intel.names[PC_MAC] = "AswinPC"
    det.names.update({PC_MAC: ("desktop-x", "mDNS")}, T0)
    assert [a.client for a in det.process_query(evil())] == ["AswinPC"]


def test_saved_name_beats_the_pihole_hostname(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.names.update({PC_MAC: ("Aswins-PC", "mDNS")}, T0)
    query = q("evil-c2.example", 0, name="(192.0.2.10, 02:00:00:00:00:10)")
    assert [a.client for a in det.process_query(query)] == ["Aswins-PC"]


def test_silent_device_label_picks_up_a_saved_name(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.names.update({IOT_MAC: ("Smart Fridge", "SSDP")}, T0)
    from pihole_detector.model import Device
    det.process_devices([Device(hwaddr=IOT_MAC, ips=(IOT_IP,), first_seen=T0)], T0 + 1)
    assert det.labels[IOT_MAC] == "Smart Fridge"


def old_alert(det, address):
    det.jsonl.write(Alert(time=MONDAY_9AM - 3600, severity="MEDIUM", rule="beaconing", client="(old label)",
                          domain="tick.example", message="m", address=address, evidence={"interval_s": 60}))


def test_daily_report_shows_the_current_name_for_earlier_alerts(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    old_alert(det, f"{PC_IP} · {PC_MAC}")
    det.names.update({PC_MAC: ("Aswins-PC", "mDNS")}, T0)
    det.maybe_digest(MONDAY_9AM, force=True)
    text = det.telegram.messages[-1]
    assert "Aswins-PC" in text and "(old label)" not in text


# --- weekly discovery, just before the daily report --------------------------------------------

class FakeProbe:
    def __init__(self, found=None, error=None):
        self.found, self.error, self.calls = found or {}, error, []

    def __call__(self, ips, wait):
        self.calls.append((sorted(ips), wait))
        if self.error:
            raise self.error
        return self.found


def report_due(det, now):
    det.state.put("last_digest", now - 86400)  # as if yesterday's report went out
    det.state.commit()


def test_discovery_runs_on_monday_at_report_time_and_saves_the_names(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.probe = FakeProbe({PC_IP: {"mDNS": "Aswins-PC", "NetBIOS": "ASWINPC"}})
    report_due(det, MONDAY_9AM)
    det.tick(MONDAY_9AM)
    assert det.probe.calls == [(sorted([PC_IP, IOT_IP]), det.cfg.discovery_wait)]
    assert det.names.name(PC_MAC) == "Aswins-PC"  # the better probe, not NetBIOS
    assert NameStore(tmp_path / "names.json").name(PC_MAC) == "Aswins-PC"  # and it is on disk


def test_discovery_runs_only_once_that_day(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.probe = FakeProbe({PC_IP: {"mDNS": "Aswins-PC"}})
    report_due(det, MONDAY_9AM)
    det.tick(MONDAY_9AM)
    det.tick(MONDAY_9AM + 600)
    assert len(det.probe.calls) == 1


def test_discovery_does_not_run_on_other_days_or_before_the_report_hour(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.probe = FakeProbe()
    report_due(det, TUESDAY_9AM)
    det.tick(TUESDAY_9AM)
    det.tick(MONDAY_9AM - 3600)  # Monday 08:05
    assert det.probe.calls == []


def test_the_report_that_follows_discovery_already_shows_the_new_names(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    old_alert(det, f"{PC_IP} · {PC_MAC}")
    det.probe = FakeProbe({PC_IP: {"mDNS": "Aswins-PC"}})
    report_due(det, MONDAY_9AM)
    det.tick(MONDAY_9AM)
    assert "Aswins-PC" in det.telegram.messages[-1]


def test_a_failed_discovery_does_not_stop_the_report(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    det.probe = FakeProbe(error=OSError("network unreachable"))
    report_due(det, MONDAY_9AM)
    det.tick(MONDAY_9AM)
    assert "Pi-hole daily report" in det.telegram.messages[-1]


def test_a_names_file_saved_by_hand_is_picked_up_without_a_restart(make_detector, tmp_path):
    det = with_store(make_detector(), tmp_path)
    manual = NameStore(tmp_path / "names.json")
    manual.update({PC_MAC: ("Aswins-PC", "mDNS")}, T0)
    manual.save()
    det.tick(TUESDAY_9AM)
    assert det.names.name(PC_MAC) == "Aswins-PC"
