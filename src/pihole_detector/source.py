"""Query sources: the live FTL v6 REST API, and JSONL replay for tests and demos."""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Protocol

from .model import Device, Query
from .namestore import MAC
from .rotation import Client

log = logging.getLogger(__name__)


class PiholeClient(Protocol):
    """Everything the detector, the bot and the CLI use of Pi-hole. PiholeApi talks to the real one
    over HTTP; the tests use one in-memory FakePihole (tests/conftest.py). Methods raise ApiError."""

    def get(self, path: str, params: dict | None = None) -> dict: ...
    def devices(self) -> list[Device]: ...
    def queries_since(self, since: float, until: float | None = None, disk: bool = False,
                      page: int = 1000, filters: dict | None = None) -> list[Query]: ...
    def clients(self) -> list[Client]: ...
    def groups(self) -> dict[int, str]: ...
    def add_domain(self, list_type: str, kind: str, domain: str, comment: str = "") -> None: ...
    def delete_domain(self, list_type: str, kind: str, domain: str) -> None: ...
    def set_blocking(self, enabled: bool, timer: int | None = None) -> None: ...
    def add_client(self, entry: Client) -> None: ...
    def update_client(self, entry: Client) -> None: ...
    def delete_client(self, client: str) -> None: ...
    def logout(self) -> None: ...


class ApiError(Exception):
    pass


class PiholeApi:
    """Minimal FTL v6 client. One session, re-authenticated on 401, logged out on close.

    FTL allows only `webserver.api.max_sessions` (16) concurrent sessions and they expire after
    30 min idle, so the detector must reuse a single SID rather than logging in per request.
    """

    def __init__(self, base_url: str, password: str, opener=urllib.request.urlopen, timeout: float = 10):
        self.base = base_url.rstrip("/")
        self.password = password
        self.opener = opener
        self.timeout = timeout
        self.sid: str | None = None

    def _request(self, method: str, path: str, params: dict | None = None, body: dict | None = None):
        url = f"{self.base}/api{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.sid:
            req.add_header("X-FTL-SID", self.sid)
        with self.opener(req, timeout=self.timeout) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else {}

    def login(self) -> None:
        try:
            result = self._request("POST", "/auth", body={"password": self.password})
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise ApiError(f"login failed: {exc}") from exc
        session = result.get("session") or {}
        if not session.get("valid"):
            raise ApiError(f"login rejected: {session.get('message') or 'invalid password'}")
        self.sid = session.get("sid")  # None when Pi-hole has no password set

    def get(self, path: str, params: dict | None = None) -> dict:
        return self._call("GET", path, params)

    def _call(self, method: str, path: str, params: dict | None = None, body: dict | None = None) -> dict:
        for attempt in (1, 2):
            if self.sid is None and self.password:
                self.login()
            try:
                return self._request(method, path, params, body)
            except urllib.error.HTTPError as exc:
                if exc.code == 401 and attempt == 1:
                    self.sid = None  # expired; log in again once
                    continue
                raise ApiError(f"{method} {path}: HTTP {exc.code}") from exc
            except (urllib.error.URLError, OSError, ValueError) as exc:
                raise ApiError(f"{method} {path}: {exc}") from exc
        raise ApiError(f"{method} {path}: unauthorised")

    def logout(self) -> None:
        if not self.sid:
            return
        try:
            self._request("DELETE", "/auth")
        except Exception:
            pass
        self.sid = None

    # endpoints --------------------------------------------------------------
    def queries_since(self, since: float, until: float | None = None, disk: bool = False,
                      page: int = 1000, filters: dict | None = None) -> list[Query]:
        """All queries with time >= since, oldest first.

        FTL returns newest first. Rather than relying on cursor/start semantics, page backwards
        by moving `until` to the oldest time seen and de-duplicating the overlap by id.
        """
        length = page
        params: dict[str, object] = {"from": f"{since:.6f}", "length": length}
        if until is not None:
            params["until"] = f"{until:.6f}"
        if disk:
            params["disk"] = "true"
        params.update(filters or {})  # e.g. {"client_ip": ...}: FTL filters server-side
        found: dict[tuple, Query] = {}
        while True:
            batch = [Query.from_api(item) for item in self.get("/queries", params).get("queries") or []]
            fresh = [q for q in batch if q.key not in found]
            for q in fresh:
                found[q.key] = q
            if len(batch) < length:
                break
            if not fresh:
                # A full page that is entirely overlap: more rows share one timestamp than fit.
                if length >= 100_000:
                    break
                length *= 2
                params["length"] = length
                continue
            params["until"] = f"{min(q.time for q in batch):.6f}"
        return sorted(found.values(), key=lambda q: (q.time, q.id))

    def devices(self) -> list[Device]:
        result = self.get("/network/devices", {"max_devices": 500, "max_addresses": 10})
        return [Device.from_api(item) for item in result.get("devices") or []]

    def clients(self) -> list[Client]:
        """The Pi-hole Clients entries that are MACs (not IPs, subnets or hostnames)."""
        out = []
        for item in self.get("/clients").get("clients") or []:
            mac = (item.get("client") or "").lower()
            if MAC.fullmatch(mac):
                out.append(Client(mac=mac, client=item["client"], comment=item.get("comment") or "",
                                  groups=tuple(item.get("groups") or ())))
        return out

    def groups(self) -> dict[int, str]:
        return {g["id"]: g["name"] for g in self.get("/groups").get("groups") or []}

    def add_domain(self, list_type: str, kind: str, domain: str, comment: str = "") -> None:
        """Add to Pi-hole's allow/deny list ("allow"|"deny", "exact"|"regex"), for every client (Default group)."""
        self._call("POST", f"/domains/{list_type}/{kind}",
                   body={"domain": domain, "comment": comment, "groups": [0], "enabled": True})

    def delete_domain(self, list_type: str, kind: str, domain: str) -> None:
        self._call("DELETE", f"/domains/{list_type}/{kind}/" + urllib.parse.quote(domain, safe=""))

    def add_client(self, entry: Client) -> None:
        self._call("POST", "/clients", body={"client": entry.client, "comment": entry.comment,
                                             "groups": list(entry.groups)})

    def update_client(self, entry: Client) -> None:
        self._call("PUT", "/clients/" + urllib.parse.quote(entry.client, safe=""),
                   body={"comment": entry.comment, "groups": list(entry.groups)})

    def set_blocking(self, enabled: bool, timer: int | None = None) -> None:
        """Turn blocking on or off; a timer (seconds) makes Pi-hole itself flip it back."""
        self._call("POST", "/dns/blocking", body={"blocking": enabled, "timer": timer})

    def delete_client(self, client: str) -> None:
        self._call("DELETE", "/clients/" + urllib.parse.quote(client, safe=""))


class Tail:
    """Turns repeated overlapping polls into a stream of each query exactly once.

    A query polled before its answer arrives has reply UNKNOWN; it is held back for up to
    `settle` seconds so rules see the final reply. Some stay UNKNOWN forever (FTL does not
    answer a client's retransmitted duplicate), so after `settle` they are released as-is.
    """

    UNSETTLED = {None, "UNKNOWN"}

    def __init__(self, start: float, settle: float = 5.0, overlap: float = 2.0):
        self.mark = start          # poll from here (minus overlap) next time
        self.settle = settle
        self.overlap = overlap
        self.done: set[tuple] = set()

    @property
    def since(self) -> float:
        return self.mark - self.overlap

    def feed(self, queries: list[Query], now: float) -> list[Query]:
        ready, pending = [], []
        for q in queries:
            if q.key in self.done:
                continue
            if q.reply in self.UNSETTLED and now - q.time < self.settle:
                pending.append(q)
                continue
            ready.append(q)
            self.done.add(q.key)
        if queries:
            newest = max(q.time for q in queries)
            self.mark = min([newest] + [q.time for q in pending])
        floor = self.since
        self.done = {k for k in self.done if k[1] >= floor}
        return ready


def read_replay(path: str | Path):
    """Yield ("query", Query) / ("devices", [Device]) events from a replay JSONL file.

    Lines are FTL `/api/queries` items, or `{"_devices": [<api device>, ...]}` snapshots.
    """
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            item = json.loads(line)
            if "_devices" in item:
                yield "devices", [Device.from_api(d) for d in item["_devices"]], float(item.get("time", 0))
            else:
                q = Query.from_api(item)
                yield "query", q, q.time
