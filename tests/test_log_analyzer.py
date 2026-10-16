import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest
from log_analyzer import SSHEvent, analyze_events, parse_line, parse_log


def test_parse_failed_password_line():
    line = "Oct 16 10:00:00 host sshd[123]: Failed password for invalid user admin from 192.0.2.10 port 2222 ssh2"
    event = parse_line(line, 1)
    assert event is not None
    assert event.source_ip == "192.0.2.10"
    assert event.outcome == "failure"
    assert event.timestamp == "Oct 16 10:00:00"


def test_parse_successful_public_key_line():
    line = "Oct 16 10:01:00 host sshd[123]: Accepted publickey for alice from 192.0.2.20 port 2222 ssh2"
    event = parse_line(line, 2)
    assert event is not None
    assert event.source_ip == "192.0.2.20"
    assert event.outcome == "success"


def test_unrelated_line_is_ignored():
    assert parse_line("Oct 16 10:00:00 host systemd[1]: Started service", 1) is None


def test_repeated_failures_trigger_alert():
    events = [
        SSHEvent(i, "Oct 16 10:00:00", "192.0.2.10", "failure", "synthetic")
        for i in range(1, 6)
    ]
    alerts = analyze_events(events, threshold=5)
    assert any(alert.rule == "repeated_failed_logins" for alert in alerts)


def test_success_after_threshold_failures_triggers_alert():
    events = [
        SSHEvent(i, "Oct 16 10:00:00", "192.0.2.10", "failure", "synthetic")
        for i in range(1, 6)
    ]
    events.append(SSHEvent(6, "Oct 16 10:01:00", "192.0.2.10", "success", "synthetic"))
    alerts = analyze_events(events, threshold=5)
    assert any(alert.rule == "success_after_repeated_failures" for alert in alerts)


def test_below_threshold_does_not_trigger_failure_alert():
    events = [
        SSHEvent(i, "Oct 16 10:00:00", "192.0.2.10", "failure", "synthetic")
        for i in range(1, 4)
    ]
    alerts = analyze_events(events, threshold=5)
    assert not any(alert.rule == "repeated_failed_logins" for alert in alerts)


def test_invalid_threshold_raises():
    with pytest.raises(ValueError):
        analyze_events([], threshold=0)
