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
        self.writes = []

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
                {"hwaddr": "02:00:00:00:00:10", "firstSeen": T0, "lastQuery": T0 + 60, "macVendor": "Acme",
                 "ips": [{"ip": "192.0.2.10", "name": "pc.lan"}]}]}).encode())
        if path.startswith("/groups"):
            return FakeResp(json.dumps({"groups": [{"id": 0, "name": "Default"}, {"id": 1, "name": "Aswin"}]}).encode())
        if path.startswith("/clients"):
            self.writes.append((req.get_method(), path, json.loads(req.data) if req.data else None))
            if req.get_method() == "GET":
                return FakeResp(json.dumps({"clients": [
                    {"client": "EA:65:E1:2F:E9:83", "comment": "iPad", "groups": [0, 1], "name": "", "id": 3},
                    {"client": "192.0.2.10", "comment": "by IP", "groups": [0], "name": "", "id": 4}]}).encode())
            return FakeResp(b"" if req.get_method() == "DELETE" else b'{"processed": {"errors": []}}')
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


def test_devices_carry_their_last_query_time():
    assert PiholeApi("http://pihole:8081", "pw", opener=FakeFtl([])).devices()[0].last_query == T0 + 60


def test_clients_lists_mac_entries_only_lowercased_but_keeps_pihole_spelling():
    from pihole_detector.rotation import Client
    assert PiholeApi("http://pihole:8081", "pw", opener=FakeFtl([])).clients() == [
        Client(mac="ea:65:e1:2f:e9:83", client="EA:65:E1:2F:E9:83", comment="iPad", groups=(0, 1))]


def test_groups_maps_ids_to_names():
    assert PiholeApi("http://pihole:8081", "pw", opener=FakeFtl([])).groups() == {0: "Default", 1: "Aswin"}


def test_client_writes_send_the_entry_and_reauthenticate_once():
    from pihole_detector.rotation import Client
    ftl = FakeFtl([], expire_after=2)  # the session dies on the first write
    api = PiholeApi("http://pihole:8081", "pw", opener=ftl)
    api.add_client(Client(mac="06:da:8f:c5:97:97", client="06:da:8f:c5:97:97", comment="iPad", groups=(0, 1)))
    api.delete_client("EA:65:E1:2F:E9:83")
    assert ftl.writes == [
        ("POST", "/clients", {"client": "06:da:8f:c5:97:97", "comment": "iPad", "groups": [0, 1]}),
        ("DELETE", "/clients/EA%3A65%3AE1%3A2F%3AE9%3A83", None)]
    assert ftl.logins == 2


def test_logout_deletes_session():
    ftl = FakeFtl([])
    api = PiholeApi("http://pihole:8081", "pw", opener=ftl)
    api.devices()
    api.logout()
    assert ftl.calls[-1] == ("DELETE", "/auth") and api.sid is None


# tail -------------------------------------------------------------------------
from pihole_detector.model import Query
from pihole_detector.source import Tail


def mk(i, t, reply="IP"):
    return Query(id=i, time=T0 + t, domain=f"d{i}.example", type="A", status="FORWARDED",
                 reply=reply, client_ip="192.0.2.10")


def test_tail_emits_each_query_once_across_overlapping_polls():
    tail = Tail(T0)
    assert [q.id for q in tail.feed([mk(1, 0), mk(2, 1)], now=T0 + 10)] == [1, 2]
    assert [q.id for q in tail.feed([mk(2, 1), mk(3, 2)], now=T0 + 11)] == [3]
    assert tail.since == T0 + 2 - 2


def test_tail_holds_unanswered_until_reply_or_settle_timeout():
    tail = Tail(T0, settle=5)
    assert tail.feed([mk(1, 0, "UNKNOWN"), mk(2, 1)], now=T0 + 1.5) == [mk(2, 1)]
    assert tail.since <= T0                       # next poll still covers the pending query
    out = tail.feed([mk(1, 0, "NXDOMAIN"), mk(2, 1)], now=T0 + 3)
    assert [(q.id, q.reply) for q in out] == [(1, "NXDOMAIN")]
    # a retransmitted duplicate that FTL never answers is released after `settle`
    tail = Tail(T0, settle=5)
    assert tail.feed([mk(7, 0, "UNKNOWN")], now=T0 + 1) == []
    assert [q.id for q in tail.feed([mk(7, 0, "UNKNOWN")], now=T0 + 6)] == [7]
    assert tail.feed([mk(7, 0, "UNKNOWN")], now=T0 + 7) == []


def test_config_strips_crlf_from_env_values():
    from pihole_detector.config import Config
    cfg = Config.from_env({"TELEGRAM_TOKEN": "123:abc\r", "PUSH_ENABLED": "true\r", "POLL_SECONDS": " 2 "})
    assert cfg.telegram_token == "123:abc" and cfg.push_enabled is True and cfg.poll_seconds == 2.0


# sinks ------------------------------------------------------------------------
def alert(sev="HIGH", rule="ti_match", msg="m", block=None):
    return Alert(time=T0, severity=sev, rule=rule, client="c", domain="d", message=msg,
                 evidence={"block": block}, dedup=rule)


def test_push_cap_mutes_once_then_recovers():
    tg = FakeTelegram(cap=3)
    sent = [tg.send(f"m{i}", T0 + i) for i in range(6)]
    assert sent == [True, True, True, False, False, False]
    assert len(tg.messages) == 4 and "Too many alerts" in tg.messages[3]
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
    assert "<code>cmd</code>" in format_push(alert(block="cmd"))
    assert "To block" not in format_push(alert())


def test_format_push_escapes_html_and_hides_duplicate_ip():
    a = Alert(time=T0, severity="MEDIUM", rule="dga_single", client="192.0.2.5", domain="a<b>.example",
              message="m", address="192.0.2.5 · 02:00:00:00:00:05")
    text = format_push(a)
    assert "a&lt;b&gt;.example" in text and "<b>.example" not in text
    assert "<i>02:00:00:00:00:05</i>" in text


def test_html_rejected_falls_back_to_plain_text():
    calls = []

    def opener(req, timeout=None):
        body = json.loads(req.data)
        calls.append(body)
        if "parse_mode" in body:
            raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {}, None)
        return FakeResp(b"{}")
    assert Telegram("t", "c", 5, opener=opener).send("<b>hi</b> &amp; bye", T0)
    assert calls[-1]["text"] == "hi & bye" and "parse_mode" not in calls[-1]


def test_digest_lists_medium_low_and_is_sent_even_when_empty():
    text = build_digest([alert("HIGH").to_dict(), alert("MEDIUM", "beaconing", "beacon msg").to_dict()],
                        {"queries": 42})
    assert "1 high" in text and "1 medium" in text and "Regular check-ins" in text and "42 lookups" in text
    assert text.index("Malware") < text.index("Regular check-ins")   # HIGH listed first
    assert "Nothing suspicious" in build_digest([], {})


# --- Bot API transport: buttons, 429, spacing, long polling, documents, command menu -----------

def recorder(results=None, fail=None):
    """An opener that records (method, payload) and answers {"ok": true, "result": ...}."""
    calls = []

    def opener(req, timeout=None):
        method = req.full_url.rsplit("/", 1)[1]
        is_json = (req.get_header("Content-type") or "").startswith("application/json")
        calls.append((method, json.loads(req.data) if is_json and req.data else req.data, timeout))
        if fail:
            err = fail(method, len(calls))
            if err:
                raise err
        result = (results or {}).get(method, True)
        return FakeResp(json.dumps({"ok": True, "result": result}).encode())
    return opener, calls


def http_429(retry_after):
    body = json.dumps({"ok": False, "error_code": 429, "parameters": {"retry_after": retry_after}}).encode()
    return urllib.error.HTTPError("https://api.telegram.org/x", 429, "Too Many Requests", {}, io.BytesIO(body))


def test_send_attaches_inline_buttons():
    opener, calls = recorder({"sendMessage": {"message_id": 7}})
    tg = Telegram("t", "42", 5, opener=opener, sleep=lambda s: None)
    rows = [[{"text": "🛡 Block", "callback_data": "a:1", "style": "danger"}]]
    assert tg.send("hi", T0, buttons=rows)
    assert calls[0][1]["reply_markup"] == {"inline_keyboard": rows}


def test_flood_control_waits_retry_after_once_then_retries():
    slept = []
    opener, calls = recorder(fail=lambda method, n: http_429(3) if n == 1 else None)
    tg = Telegram("t", "42", 5, opener=opener, sleep=slept.append, clock=lambda: 1000.0)
    assert tg.send("hi", T0, capped=False)
    assert len(calls) == 2 and 3 in slept


def test_messages_are_spaced_a_second_apart():
    slept, clock = [], [1000.0]
    opener, _ = recorder()
    tg = Telegram("t", "42", 5, opener=opener, sleep=lambda s: slept.append(s) or clock.__setitem__(0, clock[0] + s),
                  clock=lambda: clock[0])
    tg.send("a", T0, capped=False)
    clock[0] += 0.25
    tg.send("b", T0, capped=False)
    assert slept == [0.75]


def test_get_updates_long_polls_for_messages_and_buttons_only():
    opener, calls = recorder({"getUpdates": [{"update_id": 5}]})
    tg = Telegram("t", "42", 5, opener=opener, sleep=lambda s: None)
    assert tg.get_updates(offset=5, timeout=25) == [{"update_id": 5}]
    method, payload, timeout = calls[0]
    assert method == "getUpdates" and payload == {"offset": 5, "timeout": 25,
                                                   "allowed_updates": ["message", "callback_query"]}
    assert timeout > 25  # the HTTP timeout outlasts the long poll


def test_get_updates_failure_is_an_empty_batch_and_never_logs_the_token(caplog):
    def boom(req, timeout=None):
        raise urllib.error.URLError("secret-token in a url")
    assert Telegram("secret-token", "42", 5, opener=boom, sleep=lambda s: None).get_updates(0, 25) == []
    assert "secret-token" not in caplog.text


def test_send_document_uploads_a_named_file_to_the_chat():
    opener, calls = recorder()
    tg = Telegram("t", "42", 5, opener=opener, sleep=lambda s: None)
    assert tg.send_document("report.md", b"# Review\n", caption="7 days")
    method, body, _ = calls[0]
    assert method == "sendDocument"
    assert b'filename="report.md"' in body and b"# Review" in body and b'name="chat_id"' in body and b"42" in body


def test_command_menu_is_registered_for_the_owner_chat_only():
    opener, calls = recorder()
    Telegram("t", "42", 5, opener=opener, sleep=lambda s: None).set_commands([("status", "Health")])
    assert calls[0][1] == {"commands": [{"command": "status", "description": "Health"}],
                           "scope": {"type": "chat", "chat_id": "42"}}


def test_callback_answers_and_edits_are_sent():
    opener, calls = recorder()
    tg = Telegram("t", "42", 5, opener=opener, sleep=lambda s: None)
    tg.answer_callback("cb1", "Done")
    tg.edit(9, "new text")
    assert calls[0][:2] == ("answerCallbackQuery", {"callback_query_id": "cb1", "text": "Done"})
    assert calls[1][0] == "editMessageText" and calls[1][1]["message_id"] == 9 and calls[1][1]["chat_id"] == "42"
