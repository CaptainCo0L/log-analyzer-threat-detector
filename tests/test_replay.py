"""End-to-end: fixtures through the real CLI replay path."""

import json
from collections import Counter
from pathlib import Path

import pytest

from pihole_detector.__main__ import main

FIXTURES = Path(__file__).parent / "fixtures"
ALL_RULES = {"ti_match", "doh_bypass", "dga_single", "nxdomain_burst", "tunneling", "beaconing",
             "iot_off_baseline", "new_device", "device_silent"}


@pytest.fixture
def replay(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_FILE", str(FIXTURES / "threats.txt"))
    monkeypatch.setenv("EXTRA_IOT_CLIENTS", "02:00:00:00:00:20")
    monkeypatch.setenv("GRAVITY_DB", str(tmp_path / "none.db"))
    monkeypatch.setenv("TZ", "UTC")

    def run(name):
        out = tmp_path / "alerts.jsonl"
        assert main(["replay", str(FIXTURES / name), "--alerts-out", str(out)]) == 0
        return [json.loads(line) for line in out.read_text().splitlines()] if out.exists() else []
    return run


def test_attack_mix_raises_each_rule_exactly_once(replay):
    alerts = replay("attack_mix.jsonl")
    counts = Counter(a["rule"] for a in alerts)
    assert set(counts) == ALL_RULES, counts
    assert all(n == 1 for n in counts.values()), counts


def test_benign_day_is_silent(replay):
    assert replay("benign_day.jsonl") == []
