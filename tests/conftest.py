"""Shared helpers. All data is synthetic: RFC 5737 IPs, locally-administered MACs, example domains."""

from __future__ import annotations

import pytest

from pihole_detector.config import Config
from pihole_detector.detector import Detector
from pihole_detector.intel import GravityIntel
from pihole_detector.model import Device, Query
from pihole_detector.sinks import JsonlSink, Telegram
from pihole_detector.state import State

T0 = 1_760_000_000.0  # fixed clock; tests never read the wall clock
PC_IP, PC_MAC = "192.0.2.10", "02:00:00:00:00:10"
IOT_IP, IOT_MAC = "192.0.2.20", "02:00:00:00:00:20"


class FakeTelegram(Telegram):
    def __init__(self, cap=20):
        super().__init__("token", "chat", cap)
        self.messages: list[str] = []

    def _post(self, text: str) -> bool:
        self.messages.append(text)
        return True


def q(domain, t=0.0, ip=PC_IP, reply="IP", status="FORWARDED", qtype="A", **kw) -> Query:
    return Query(id=0, time=T0 + t, domain=domain, type=qtype, status=status, reply=reply,
                 client_ip=ip, client_name=kw.pop("name", None), **kw)


@pytest.fixture
def make_detector(tmp_path):
    def factory(threats=("evil-c2.example",), iot=(IOT_MAC,), **cfg_overrides):
        cfg_overrides.setdefault("names_file", str(tmp_path / "names.json"))
        cfg = Config(gravity_db=str(tmp_path / "missing.db"), **cfg_overrides)
        intel = GravityIntel(tmp_path / "missing.db", "tif", "IoT", extra_threats=threats, extra_iot=iot)
        det = Detector(cfg, State(":memory:"), intel, JsonlSink(tmp_path / "alerts.jsonl"), FakeTelegram(),
                       probe=lambda ips, wait, **_: {})  # never touch the real network
        det.process_devices([
            Device(hwaddr=PC_MAC, ips=(PC_IP,), first_seen=T0),
            Device(hwaddr=IOT_MAC, ips=(IOT_IP,), first_seen=T0),
        ], T0)
        return det
    return factory


def rules_of(alerts) -> list[str]:
    return [a.rule for a in alerts]
