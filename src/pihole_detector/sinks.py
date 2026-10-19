"""Alert outputs: JSONL audit trail, Telegram push (rate-capped), daily digest."""

from __future__ import annotations

import json
import logging
import urllib.request
from collections import Counter, deque
from pathlib import Path

from .model import HIGH, Alert

log = logging.getLogger(__name__)
TELEGRAM_LIMIT = 4000


class JsonlSink:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, alert: Alert) -> None:
        with open(self.path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(alert.to_dict(), sort_keys=True) + "\n")

    def since(self, start: float) -> list[dict]:
        if not self.path.exists():
            return []
        out = []
        with open(self.path, encoding="utf-8") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if record.get("time", 0) >= start:
                    out.append(record)
        return out


class Telegram:
    """Sends messages through the Bot API. Never raises: a push failure must not stop detection."""

    def __init__(self, token: str, chat_id: str, cap_per_hour: int, opener=urllib.request.urlopen):
        self.token = token
        self.chat_id = chat_id
        self.cap = cap_per_hour
        self.sent: deque[float] = deque()
        self.muted = False
        self.opener = opener

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def _post(self, text: str) -> bool:
        if not self.configured:
            log.info("telegram not configured; would send: %s", text[:200])
            return False
        body = json.dumps({"chat_id": self.chat_id, "text": text[:TELEGRAM_LIMIT],
                           "disable_web_page_preview": True}).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{self.token}/sendMessage", data=body,
            headers={"Content-Type": "application/json"},
        )
        try:
            with self.opener(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:  # network, HTTP 4xx/5xx
            # Never log the URL: it contains the bot token.
            log.warning("telegram send failed: %s", type(exc).__name__)
            return False

    def send(self, text: str, now: float, capped: bool = True) -> bool:
        if capped:
            while self.sent and self.sent[0] < now - 3600:
                self.sent.popleft()
            if len(self.sent) >= self.cap:
                if not self.muted:
                    self.muted = True
                    self._post(f"Alert cap of {self.cap}/h reached; further pushes muted for up to an hour. "
                               "Everything is still written to alerts.jsonl.")
                return False
            self.muted = False
            self.sent.append(now)
        return self._post(text)


def format_push(alert: Alert) -> str:
    text = f"[{alert.severity}] {alert.rule}\n{alert.message}"
    block = alert.evidence.get("block") if alert.evidence else None
    if block:
        text += f"\nTo block: {block}"
    return text


def build_digest(records: list[dict], stats: dict) -> str:
    """One daily message. Always sent, even when empty: a missing digest means the detector died."""
    by_sev = Counter(r["severity"] for r in records)
    by_rule = Counter(r["rule"] for r in records)
    lines = [
        "Pi-hole detector - daily digest",
        f"Queries analysed: {stats.get('queries', 0)} | API failures: {stats.get('api_failures', 0)}",
        "Alerts: " + (", ".join(f"{s} {by_sev[s]}" for s in ("HIGH", "MEDIUM", "LOW") if by_sev[s]) or "none"),
    ]
    if by_rule:
        lines.append("By rule: " + ", ".join(f"{r} {n}" for r, n in by_rule.most_common()))
    detail = [r for r in records if r["severity"] != HIGH]
    if detail:
        lines.append("")
        for r in detail[:30]:
            lines.append(f"- [{r['severity']}] {r['message']}")
        if len(detail) > 30:
            lines.append(f"... and {len(detail) - 30} more in alerts.jsonl")
    return "\n".join(lines)
