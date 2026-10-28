"""Shared helpers. All data is synthetic: RFC 5737 IPs, locally-administered MACs, example domains."""

from __future__ import annotations

import pytest

from pihole_detector.config import Config
from pihole_detector.detector import Detector
from pihole_detector.intel import GravityIntel
from pihole_detector.model import Device, Query
from pihole_detector.alertlog import AlertLog
from pihole_detector.sinks import Telegram
from pihole_detector.state import State

T0 = 1_760_000_000.0  # fixed clock; tests never read the wall clock
PC_IP, PC_MAC = "192.0.2.10", "02:00:00:00:00:10"
IOT_IP, IOT_MAC = "192.0.2.20", "02:00:00:00:00:20"


class FakeTelegram(Telegram):
    """Records every Bot API call instead of sending it. `updates` scripts getUpdates batches."""

    def __init__(self, chat_id="42"):
        super().__init__("token", chat_id, sleep=lambda s: None)
        self.calls: list[tuple[str, dict, dict | None]] = []
        self.updates: list[list[dict]] = []

    def _api(self, method, payload=None, files=None, timeout=10):
        self.calls.append((method, payload or {}, files))
        if method == "getUpdates":
            return self.updates.pop(0) if self.updates else []
        if method == "sendMessage":
            return {"message_id": len(self.calls)}
        return True

    def payloads(self, method="sendMessage") -> list[dict]:
        return [payload for m, payload, _ in self.calls if m == method]

    @property
    def messages(self) -> list[str]:
        return [payload["text"] for payload in self.payloads()]


class FakePihole:
    """Pi-hole in memory: the whole PiholeClient protocol (source.py), so every test fakes the same seam.

    Writes are recorded in `calls` as ("add_domain", type, kind, domain), ("delete_domain", ...),
    ("blocking", enabled, timer), ("add_client" | "update_client", client, comment, groups) and
    ("delete_client", client). `fail` maps a method to the ApiError text it raises, `missing` holds
    domains whose delete 404s, and `down` makes every read fail like an unreachable Pi-hole.
    """

    def __init__(self, devices=(), clients=(), queries=(), groups=None, fail=None):
        self.devices_, self.entries, self.queries = list(devices), list(clients), list(queries)
        self.groups_ = groups or {0: "Default", 1: "Aswin", 2: "IoT"}
        self.fail = fail or {}
        self.calls: list[tuple] = []
        self.query_calls: list[tuple] = []
        self.missing: set[str] = set()
        self.down = False
        self.logged_out = False

    def _check(self, method):
        from pihole_detector.source import ApiError
        if self.down:
            raise ApiError(f"{method}: connection refused")
        if method in self.fail:
            raise ApiError(self.fail[method])

    # reads
    def get(self, path, params=None):
        self._check("get")
        assert path == "/dns/blocking"
        return {"blocking": "enabled", "timer": None}

    def devices(self):
        self._check("devices")
        return list(self.devices_)

    def queries_since(self, since, until=None, disk=False, page=1000, filters=None):
        self._check("queries_since")
        self.query_calls.append((since, filters))
        ip = (filters or {}).get("client_ip")
        return [x for x in self.queries if x.time >= since and (until is None or x.time <= until)
                and (ip is None or x.client_ip == ip)]

    def clients(self):
        self._check("clients")
        return list(self.entries)

    def groups(self):
        self._check("groups")
        return dict(self.groups_)

    # writes
    def add_domain(self, list_type, kind, domain, comment=""):
        self._check("add_domain")
        self.calls.append(("add_domain", list_type, kind, domain))

    def delete_domain(self, list_type, kind, domain):
        self._check("delete_domain")
        if domain in self.missing:
            from pihole_detector.source import ApiError
            raise ApiError(f"DELETE /domains/{list_type}/{kind}: HTTP 404")
        self.calls.append(("delete_domain", list_type, kind, domain))

    def set_blocking(self, enabled, timer=None):
        self._check("set_blocking")
        self.calls.append(("blocking", enabled, timer))

    def add_client(self, entry):
        self._check("add_client")
        self.calls.append(("add_client", entry.client, entry.comment, entry.groups))
        self.entries.append(entry)

    def update_client(self, entry):
        self._check("update_client")
        self.calls.append(("update_client", entry.client, entry.comment, entry.groups))
        self.entries = [entry if c.client == entry.client else c for c in self.entries]

    def delete_client(self, client):
        self._check("delete_client")
        self.calls.append(("delete_client", client))
        self.entries = [c for c in self.entries if c.client != client]

    def logout(self):
        self.logged_out = True


def q(domain, t=0.0, ip=PC_IP, reply="IP", status="FORWARDED", qtype="A", **kw) -> Query:
    return Query(id=0, time=T0 + t, domain=domain, type=qtype, status=status, reply=reply,
                 client_ip=ip, client_name=kw.pop("name", None), **kw)


@pytest.fixture
def make_detector(tmp_path):
    def factory(threats=("evil-c2.example",), iot=(IOT_MAC,), **cfg_overrides):
        cfg_overrides.setdefault("names_file", str(tmp_path / "names.json"))
        cfg = Config(gravity_db=str(tmp_path / "missing.db"), **cfg_overrides)
        intel = GravityIntel(tmp_path / "missing.db", "tif", "IoT", extra_threats=threats, extra_iot=iot)
        det = Detector(cfg, State(":memory:"), intel, AlertLog(tmp_path / "alerts.jsonl"), FakeTelegram(),
                       probe=lambda ips, wait, **_: {})  # never touch the real network
        det.process_devices([
            Device(hwaddr=PC_MAC, ips=(PC_IP,), first_seen=T0),
            Device(hwaddr=IOT_MAC, ips=(IOT_IP,), first_seen=T0),
        ], T0)
        return det
    return factory


def rules_of(alerts) -> list[str]:
    return [a.rule for a in alerts]
