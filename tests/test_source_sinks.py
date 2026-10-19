import io
import json
import urllib.error

import pytest

from pihole_detector.model import Alert
from pihole_detector.sinks import Telegram, build_digest, format_push
from pihole_detector.source import ApiError, PiholeApi
from conftest import FakeTelegram, T0


class FakeResp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class FakeFtl:
    """Mimics the parts of FTL v6 the client uses: auth, sessions, newest-first queries."""

    def __init__(self, queries, page_limit=None, expire_after=None):
        self.queries = sorted(queries, key=lambda x: -x["time"])
        self.page_limit = page_limit
        self.expire_after = expire_after
        self.calls = []
        self.logins = 0
        self.sid = None

    def __call__(self, req, timeout=None):
        path = req.full_url.split("/api", 1)[1]
        self.calls.append((req.get_method(), path))
        if path.startswith("/auth"):
            if req.get_method() == "DELETE":
                return FakeResp(b"")
            body = json.loads(req.data)
            if body["password"] != "pw":
                return FakeResp(json.dumps({"session": {"valid": False, "message": "password incorrect"}}).encode())
            self.logins += 1
            self.sid = f"sid{self.logins}"
            return FakeResp(json.dumps({"session": {"valid": True, "sid": self.sid}}).encode())
        if req.get_header("X-ftl-sid") != self.sid or (self.expire_after and len(self.calls) == self.expire_after):
            self.sid = None
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
        from urllib.parse import parse_qs, urlparse
        params = {k: v[0] for k, v in parse_qs(urlparse(req.full_url).query).items()}
        if path.startswith("/queries"):
            lo, hi = float(params["from"]), float(params.get("until", "inf"))
            length = int(params["length"])
            rows = [x for x in self.queries if lo <= x["time"] <= hi][:length]
            return FakeResp(json.dumps({"queries": rows, "cursor": 1}).encode())
        if path.startswith("/network/devices"):
            return FakeResp(json.dumps({"devices": [
                {"hwaddr": "02:00:00:00:00:10", "firstSeen": T0, "macVendor": "Acme",
                 "ips": [{"ip": "192.0.2.10", "name": "pc.lan"}]}]}).encode())
        raise AssertionError(path)


def api_rows(n, step=1.0):
    return [{"id": i + 1, "time": T0 + i * step, "type": "A", "domain": f"d{i}.example", "status": "FORWARDED",
             "client": {"ip": "192.0.2.10", "name": None}, "reply": {"type": "IP", "time": 1}, "list_id": None}
            for i in range(n)]


def test_queries_since_pages_backwards_without_gaps_or_duplicates():
    ftl = FakeFtl(api_rows(2500))
    api = PiholeApi("http://pihole:8081", "pw", opener=ftl)
    got = api.queries_since(T0, page=1000)
    assert [q.id for q in got] == list(range(1, 2501))
    assert ftl.logins == 1


def test_overlapping_timestamps_across_pages():
    rows = api_rows(30, step=0)   # all at the same instant, ids differ
    api = PiholeApi("http://pihole:8081", "pw", opener=FakeFtl(rows))
    assert len(api.queries_since(T0, page=10)) == 30


def test_reauthenticates_once_on_401():
    ftl = FakeFtl(api_rows(5), expire_after=3)
    api = PiholeApi("http://pihole:8081", "pw", opener=ftl)
    api.queries_since(T0)          # login + first GET
    api.queries_since(T0)          # 3rd call -> 401 -> re-login -> retry
    assert ftl.logins == 2


def test_wrong_password_raises_api_error():
    api = PiholeApi("http://pihole:8081", "nope", opener=FakeFtl([]))
    with pytest.raises(ApiError, match="password incorrect"):
        api.devices()


def test_unreachable_raises_api_error():
    def down(req, timeout=None):
        raise urllib.error.URLError("connection refused")
    with pytest.raises(ApiError):
        PiholeApi("http://pihole:8081", "pw", opener=down).devices()


def test_devices_parsed_with_names():
    dev = PiholeApi("http://pihole:8081", "pw", opener=FakeFtl([])).devices()[0]
    assert dev.hwaddr == "02:00:00:00:00:10" and dev.name == "pc.lan" and dev.is_real_mac


def test_logout_deletes_session():
    ftl = FakeFtl([])
    api = PiholeApi("http://pihole:8081", "pw", opener=ftl)
    api.devices()
    api.logout()
    assert ftl.calls[-1] == ("DELETE", "/auth") and api.sid is None


# sinks ------------------------------------------------------------------------
def alert(sev="HIGH", rule="ti_match", msg="m", block=None):
    return Alert(time=T0, severity=sev, rule=rule, client="c", domain="d", message=msg,
                 evidence={"block": block}, dedup=rule)


def test_push_cap_mutes_once_then_recovers():
    tg = FakeTelegram(cap=3)
    sent = [tg.send(f"m{i}", T0 + i) for i in range(6)]
    assert sent == [True, True, True, False, False, False]
    assert len(tg.messages) == 4 and "muted" in tg.messages[3]
    assert tg.send("later", T0 + 3601)
    assert tg.messages[-1] == "later"


def test_uncapped_messages_bypass_cap():
    tg = FakeTelegram(cap=0)
    assert tg.send("health", T0, capped=False)


def test_unconfigured_telegram_never_raises():
    assert Telegram("", "", 5).send("x", T0) is False


def test_telegram_failure_is_swallowed():
    def boom(req, timeout=None):
        raise urllib.error.URLError("dns down")
    assert Telegram("t", "c", 5, opener=boom).send("x", T0) is False


def test_format_push_includes_block_hint():
    assert "To block: cmd" in format_push(alert(block="cmd"))
    assert "To block" not in format_push(alert())


def test_digest_lists_medium_low_and_is_sent_even_when_empty():
    text = build_digest([alert("HIGH").to_dict(), alert("MEDIUM", "beaconing", "beacon msg").to_dict()],
                        {"queries": 42})
    assert "HIGH 1" in text and "MEDIUM 1" in text and "beacon msg" in text and "42" in text
    assert "Alerts: none" in build_digest([], {})
