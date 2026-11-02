"""alerts.jsonl is never rewritten, so every reader gets one shape whatever year a line was written in."""

import json

from conftest import PC_IP, PC_MAC, T0, q
from pihole_detector.alertlog import AlertLog, upgrade
from pihole_detector.model import Alert

MAC = "02:00:00:00:00:0a"


def old_line(**fields):
    return {"time": T0, "severity": "HIGH", "rule": "ti_match", "domain": "x.example", "message": "m", **fields}


def test_a_line_from_before_the_fields_existed_reads_like_a_new_one():
    record = upgrade(old_line(client="Pixel", address=f"192.0.2.10 · {MAC}", dedup=f"ti_match|{MAC}|x.example"))
    assert (record["label"], record["ips"], record["mac"], record["device"]) == ("Pixel", ["192.0.2.10"], MAC, MAC)
    assert "client" not in record and "address" not in record


def test_a_query_rule_line_with_no_mac_is_about_its_ip():
    record = upgrade(old_line(client="192.0.2.10", address="192.0.2.10", dedup="ti_match|192.0.2.10|x.example"))
    assert (record["ips"], record["mac"], record["device"]) == (["192.0.2.10"], "", "192.0.2.10")


def test_a_new_device_line_keeps_both_its_ips():
    record = upgrade(old_line(rule="new_device", client="TV", address=f"192.0.2.10 · fe80::1 · {MAC}",
                              dedup=f"new_device|{MAC}"))
    assert (record["ips"], record["mac"]) == (["192.0.2.10", "fe80::1"], MAC)


def test_an_early_line_finds_its_mac_in_the_label_pihole_gave_it():
    record = upgrade(old_line(client=f"(192.0.2.10, {MAC.upper()})", address=None))
    assert (record["mac"], record["device"]) == (MAC, MAC)


def test_a_device_silent_line_held_the_identity_in_its_address():
    record = upgrade(old_line(rule="device_silent", client="iPad", address=MAC, dedup=f"device_silent|{MAC}"))
    assert (record["ips"], record["mac"], record["device"]) == ([], MAC, MAC)


def test_upgrading_twice_changes_nothing():
    once = upgrade(old_line(client="Pixel", address=f"192.0.2.10 · {MAC}"))
    assert upgrade(once) == once


def test_old_and_new_lines_read_back_the_same_way(tmp_path):
    log = AlertLog(tmp_path / "alerts.jsonl")
    log.path.write_text(json.dumps(old_line(client="Pixel", address=f"192.0.2.10 · {MAC}")) + "\n", encoding="utf-8")
    log.write(Alert(time=T0 + 1, severity="LOW", rule="beaconing", label="TV", domain="", message="m",
                    device="tv", mac=MAC, ips=("192.0.2.11",)))
    assert [(r["label"], r["ips"], r["mac"]) for r in log.read()] == [("Pixel", ["192.0.2.10"], MAC),
                                                                     ("TV", ["192.0.2.11"], MAC)]


def test_a_line_naming_no_one_is_skipped(tmp_path):
    log = AlertLog(tmp_path / "alerts.jsonl")
    log.path.write_text(json.dumps({"time": T0, "severity": "HIGH", "rule": "ti_match"}) + "\n", encoding="utf-8")
    assert log.read_counted() == ([], 1)


def test_an_alert_from_a_query_says_who_in_fields(make_detector):
    alert = make_detector().process_query(q("evil-c2.example"))[0]
    assert (alert.device, alert.mac, alert.ips, alert.address) == (PC_MAC, PC_MAC, (PC_IP,), f"{PC_IP} · {PC_MAC}")
