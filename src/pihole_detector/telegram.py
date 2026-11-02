"""The Telegram Bot API: messages, buttons, files and long polling. Knows nothing about alerts."""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
import uuid

from .sinks import TELEGRAM_LIMIT, strip_html

log = logging.getLogger(__name__)


def _retry_after(exc: urllib.error.HTTPError) -> float:
    try:
        return float(json.loads(exc.read() or b"{}").get("parameters", {}).get("retry_after", 0))
    except (ValueError, AttributeError, OSError):
        return 0.0


def _multipart(fields: dict, files: dict) -> tuple[bytes, str]:
    """multipart/form-data for sendDocument: plain fields plus {name: (filename, bytes)}."""
    boundary = uuid.uuid4().hex
    crlf = "\r\n"
    parts = []
    for name, value in fields.items():
        parts.append(f'--{boundary}{crlf}Content-Disposition: form-data; name="{name}"{crlf}{crlf}{value}{crlf}'.encode())
    for name, (filename, content) in files.items():
        head = (f'--{boundary}{crlf}Content-Disposition: form-data; name="{name}"; filename="{filename}"{crlf}'
                f"Content-Type: application/octet-stream{crlf}{crlf}")
        parts.append(head.encode() + content + crlf.encode())
    parts.append(f"--{boundary}--{crlf}".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


class TelegramError(Exception):
    def __init__(self, code: int | None, retry_after: float = 0):
        super().__init__(f"HTTP {code}" if code else "network error")
        self.code = code
        self.retry_after = retry_after


class Telegram:
    """The Bot API: sends HTML messages, buttons and files, and long-polls for updates. Never raises: a
    push failure must not stop detection. The token is part of every URL, so URLs are never logged."""

    SPACING = 1.0     # "In a single chat, avoid sending more than one message per second" (Bot FAQ)
    MAX_WAIT = 30.0   # longest flood-control wait honoured; longer ones drop the message

    def __init__(self, token: str, chat_id: str, opener=urllib.request.urlopen,
                 sleep=time.sleep, clock=time.monotonic):
        self.token = token
        self.chat_id = chat_id
        self.opener = opener
        self.sleep = sleep
        self.clock = clock
        self._last_send: float | None = None

    @property
    def configured(self) -> bool:
        return bool(self.token and self.chat_id)

    def _request(self, method: str, payload: dict | None, files, timeout: float):
        url = f"https://api.telegram.org/bot{self.token}/{method}"
        if files:
            body, content_type = _multipart(payload or {}, files)
        else:
            body, content_type = json.dumps(payload or {}).encode(), "application/json"
        req = urllib.request.Request(url, data=body, headers={"Content-Type": content_type})
        with self.opener(req, timeout=timeout) as resp:
            raw = resp.read()
        return json.loads(raw).get("result") if raw else None

    def _api(self, method: str, payload: dict | None = None, files=None, timeout: float = 10):
        """One Bot API call; waits out one flood-control 429. Raises TelegramError."""
        for attempt in (1, 2):
            try:
                return self._request(method, payload, files, timeout)
            except urllib.error.HTTPError as exc:
                retry_after = _retry_after(exc)
                if exc.code == 429 and attempt == 1 and retry_after <= self.MAX_WAIT:
                    self.sleep(retry_after)
                    continue
                raise TelegramError(exc.code, retry_after) from None
            except (urllib.error.URLError, OSError, ValueError):
                raise TelegramError(None) from None  # the cause's text may hold the URL, so drop it
        raise TelegramError(429)

    def _space(self) -> None:
        """Hold each new message until a second has passed since the previous one."""
        if self._last_send is not None:
            wait = self.SPACING - (self.clock() - self._last_send)
            if wait > 0:
                self.sleep(wait)
        self._last_send = self.clock()

    def _post(self, text: str, buttons=None, html_mode: bool = True) -> bool:
        if not self.configured:
            log.info("telegram not configured; would send: %s", strip_html(text)[:200])
            return False
        payload = {"chat_id": self.chat_id, "text": text[:TELEGRAM_LIMIT], "disable_web_page_preview": True}
        if html_mode:
            payload["parse_mode"] = "HTML"
            self._space()
        if buttons:
            payload["reply_markup"] = {"inline_keyboard": buttons}
        try:
            self._api("sendMessage", payload)
            return True
        except TelegramError as exc:
            if exc.code == 400 and html_mode:
                # Formatting rejected (e.g. odd characters): never lose the alert, resend as plain text.
                log.warning("telegram rejected HTML; resending as plain text")
                return self._post(strip_html(text), buttons, html_mode=False)
            log.warning("telegram send failed: %s", exc)
            return False

    def get_updates(self, offset: int, timeout: int = 25) -> list[dict]:
        """Long-poll for the owner's messages and button presses. [] on any failure."""
        if not self.configured:
            return []
        try:
            return self._api("getUpdates", {"offset": offset, "timeout": timeout,
                                            "allowed_updates": ["message", "callback_query"]},
                             timeout=timeout + 10) or []
        except TelegramError as exc:
            log.warning("telegram getUpdates failed: %s", exc)
            return []

    def _call(self, method: str, payload: dict, files=None) -> bool:
        if not self.configured:
            return False
        try:
            self._api(method, payload, files)
            return True
        except TelegramError as exc:
            log.warning("telegram %s failed: %s", method, exc)
            return False

    def answer_callback(self, callback_id: str, text: str = "") -> bool:
        """Stops the button's spinner; `text` (<= 200 chars) shows as a toast."""
        return self._call("answerCallbackQuery", {"callback_query_id": callback_id, "text": text[:200]})

    def edit(self, message_id: int, text: str, buttons=None) -> bool:
        payload = {"chat_id": self.chat_id, "message_id": message_id, "text": text[:TELEGRAM_LIMIT],
                   "parse_mode": "HTML", "disable_web_page_preview": True,
                   "reply_markup": {"inline_keyboard": buttons or []}}
        return self._call("editMessageText", payload)

    def send_document(self, filename: str, content: bytes, caption: str = "") -> bool:
        self._space()
        return self._call("sendDocument", {"chat_id": self.chat_id, "caption": caption[:1024]},
                          files={"document": (filename, content)})

    def set_commands(self, commands: list[tuple[str, str]]) -> bool:
        """The "/" menu, shown in the owner's chat only."""
        return self._call("setMyCommands", {
            "commands": [{"command": c, "description": d} for c, d in commands],
            "scope": {"type": "chat", "chat_id": self.chat_id}})

    def delete_webhook(self) -> bool:
        """getUpdates is refused while a webhook is set."""
        return self._call("deleteWebhook", {})

    def send(self, text: str, buttons=None) -> bool:
        return self._post(text, buttons)
