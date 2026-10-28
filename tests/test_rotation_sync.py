"""Rotation sync through the detector: the Pi-hole writes, the change log, Telegram and undo."""

import json
import time

from pihole_detector.model import Device
from pihole_detector.namestore import NameStore
from pihole_detector.rotation import Client
from conftest import T0, FakePihole

IPAD_OLD, IPAD_OLDER, IPAD_NEW = "02:00:00:00:00:30", "0a:00:00:00:00:29", "06:00:00:00:00:31"
NEW_IP = "192.0.2.31"


def entry(mac, comment="iPad", groups=(0, 1)):
    return Client(mac=mac, client=mac.upper(), comment=comment, groups=groups)


def ipad_detector(make_detector, tmp_path, api, answer=("Aswins-iPad", "mDNS"), **cfg):
    cfg.setdefault("rotation_sync", True)
    det = make_detector(client_changes_path=str(tmp_path / "client_changes.jsonl"), **cfg)
    det.names = NameStore(tmp_path / "names.json")
    det.names.update({IPAD_OLD: ("Aswins-iPad", "mDNS"), IPAD_OLDER: ("Aswins-iPad", "mDNS")}, T0)
    for mac in (IPAD_OLD, IPAD_OLDER):
        det.state.add_device(mac, T0)  # known MACs, so only the new one is "new"
    det.clients_api = api
    det.probe = lambda ips, wait, **_: {NEW_IP: {answer[1]: answer[0]}}
    return det


def rejoin(det, now=T0 + 100):
    devices = [Device(hwaddr=IPAD_OLD, ips=("192.0.2.30",), first_seen=T0, last_query=T0 + 50),
               Device(hwaddr=IPAD_OLDER, ips=("192.0.2.29",), first_seen=T0, last_query=T0 + 10),
               Device(hwaddr=IPAD_NEW, ips=(NEW_IP,), first_seen=now, last_query=now)]
    return det.process_devices(devices, now)


def test_a_rotation_adds_the_new_mac_and_drops_the_oldest(make_detector, tmp_path):
    api = FakePihole(clients=[entry(IPAD_OLD, "iPad (current)"), entry(IPAD_OLDER, "old iPad")])
    det = ipad_detector(make_detector, tmp_path, api)
    alerts = rejoin(det)
    assert api.calls == [("add_client", IPAD_NEW, "iPad (current)", (0, 1)), ("delete_client", IPAD_OLDER.upper())]
    assert [a.severity for a in alerts if a.rule == "new_device"] == ["LOW"]  # the alert is still there
    text = det.telegram.messages[-1]
    assert "Aswins-iPad" in text and IPAD_NEW in text and IPAD_OLDER in text
    assert "Default, Aswin" in text and "clients-undo" in text
    change = json.loads((tmp_path / "client_changes.jsonl").read_text().splitlines()[-1])
    assert change["added"]["mac"] == IPAD_NEW and [d["mac"] for d in change["deleted"]] == [IPAD_OLDER]


def test_rotation_sync_off_touches_nothing(make_detector, tmp_path):
    api = FakePihole(clients=[entry(IPAD_OLD)])
    det = ipad_detector(make_detector, tmp_path, api, rotation_sync=False)
    rejoin(det)
    assert api.calls == [] and not (tmp_path / "client_changes.jsonl").exists()


def test_an_untrusted_name_touches_nothing(make_detector, tmp_path):
    api = FakePihole(clients=[entry(IPAD_OLD)])
    det = ipad_detector(make_detector, tmp_path, api, answer=("Aswins-iPad", "NetBIOS"))
    rejoin(det)
    assert api.calls == []


def test_a_failed_write_keeps_the_alert_and_records_what_was_done(make_detector, tmp_path):
    api = FakePihole(clients=[entry(IPAD_OLD), entry(IPAD_OLDER)], fail={"delete_client": "DELETE: HTTP 500"})
    det = ipad_detector(make_detector, tmp_path, api)
    alerts = rejoin(det)
    assert [a.rule for a in alerts] == ["new_device"]
    change = json.loads((tmp_path / "client_changes.jsonl").read_text().splitlines()[-1])
    assert change["added"]["mac"] == IPAD_NEW and change["deleted"] == [] and "HTTP 500" in change["error"]
    assert "HTTP 500" in det.telegram.messages[-1]


def test_a_failed_add_writes_no_change(make_detector, tmp_path):
    api = FakePihole(clients=[entry(IPAD_OLD)], fail={"add_client": "POST /clients: HTTP 500"})
    det = ipad_detector(make_detector, tmp_path, api)
    assert [a.rule for a in rejoin(det)] == ["new_device"]
    assert not (tmp_path / "client_changes.jsonl").exists()


def test_weekly_discovery_syncs_a_rotation_it_missed(make_detector, tmp_path):
    api = FakePihole(clients=[entry(IPAD_OLD)])
    det = ipad_detector(make_detector, tmp_path, api)
    answer, det.probe = det.probe, lambda ips, wait, **_: {}  # asleep when it joined
    det.process_devices([Device(hwaddr=IPAD_OLD, ips=("192.0.2.30",), first_seen=T0, last_query=T0 + 50),
                         Device(hwaddr=IPAD_NEW, ips=(NEW_IP,), first_seen=T0, last_query=T0 + 60)], T0)
    assert api.calls == []
    det.probe = answer
    monday = time.mktime((2026, 10, 19, 9, 5, 0, 0, 0, -1))
    det.state.put("last_digest", monday - 86400)
    det.tick(monday)
    assert [c[:2] for c in api.calls] == [("add_client", IPAD_NEW)]


# --- clients-undo ------------------------------------------------------------------------------

from pihole_detector.__main__ import cmd_clients_undo
from pihole_detector.config import Config


def test_undo_reverses_the_last_change_once(make_detector, tmp_path, capsys):
    api = FakePihole(clients=[entry(IPAD_OLD, "iPad (current)"), entry(IPAD_OLDER, "old iPad")])
    det = ipad_detector(make_detector, tmp_path, api)
    rejoin(det)
    cfg = Config(client_changes_path=str(tmp_path / "client_changes.jsonl"))
    api.calls.clear()
    assert cmd_clients_undo(cfg, api=api) == 0
    assert api.calls == [("delete_client", IPAD_NEW), ("add_client", IPAD_OLDER.upper(), "old iPad", (0, 1))]
    assert sorted(c.mac for c in api.entries) == sorted([IPAD_OLD, IPAD_OLDER])
    api.calls.clear()
    assert cmd_clients_undo(cfg, api=api) == 1  # nothing left to undo
    assert api.calls == [] and "nothing to undo" in capsys.readouterr().out
