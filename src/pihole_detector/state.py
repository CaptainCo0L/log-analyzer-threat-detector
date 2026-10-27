"""Persistent detector state in SQLite: cursor, clients, per-client baselines, dedup."""

from __future__ import annotations

import json
import secrets
import sqlite3
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS client (
    ident TEXT PRIMARY KEY,        -- MAC when known, else IP
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    queries INTEGER NOT NULL DEFAULT 0,
    silent_alerted INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS client_domain (
    ident TEXT NOT NULL,
    apex TEXT NOT NULL,
    first_seen REAL NOT NULL,
    PRIMARY KEY (ident, apex)
);
CREATE INDEX IF NOT EXISTS idx_client_domain_apex ON client_domain (apex);
CREATE TABLE IF NOT EXISTS device (hwaddr TEXT PRIMARY KEY, first_seen REAL NOT NULL);
CREATE TABLE IF NOT EXISTS dedup (key TEXT PRIMARY KEY, until REAL NOT NULL);
CREATE TABLE IF NOT EXISTS action (id TEXT PRIMARY KEY, payload TEXT NOT NULL, created REAL NOT NULL);
"""
ACTION_TTL = 86400  # a Telegram button works for one day, and once


class State:
    def __init__(self, path: str | Path = ":memory:"):
        self.db = sqlite3.connect(str(path))
        self.db.executescript(SCHEMA)
        self.db.commit()

    def commit(self) -> None:
        self.db.commit()

    def close(self) -> None:
        self.db.commit()
        self.db.close()

    # meta -----------------------------------------------------------------
    def get(self, key: str, default=None):
        row = self.db.execute("SELECT v FROM meta WHERE k = ?", (key,)).fetchone()
        return json.loads(row[0]) if row else default

    def put(self, key: str, value) -> None:
        self.db.execute(
            "INSERT INTO meta (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (key, json.dumps(value)),
        )

    # clients and baselines --------------------------------------------------
    def touch_client(self, ident: str, now: float) -> None:
        self.db.execute(
            "INSERT INTO client (ident, first_seen, last_seen, queries) VALUES (?, ?, ?, 1) "
            "ON CONFLICT(ident) DO UPDATE SET last_seen = max(last_seen, excluded.last_seen), "
            "first_seen = min(first_seen, excluded.first_seen), queries = queries + 1, silent_alerted = 0",
            (ident, now, now),
        )

    def client_first_seen(self, ident: str) -> float | None:
        row = self.db.execute("SELECT first_seen FROM client WHERE ident = ?", (ident,)).fetchone()
        return row[0] if row else None

    def remember_domain(self, ident: str, apex: str, now: float) -> bool:
        """Add apex to the client's baseline. Returns True if it was new."""
        cur = self.db.execute(
            "INSERT OR IGNORE INTO client_domain (ident, apex, first_seen) VALUES (?, ?, ?)",
            (ident, apex, now),
        )
        return cur.rowcount == 1

    def domain_first_seen(self, ident: str, apex: str) -> float | None:
        row = self.db.execute(
            "SELECT first_seen FROM client_domain WHERE ident = ? AND apex = ?", (ident, apex)
        ).fetchone()
        return row[0] if row else None

    def apex_prevalence(self, apex: str) -> int:
        """How many clients have this apex in their baseline."""
        return self.db.execute("SELECT count(*) FROM client_domain WHERE apex = ?", (apex,)).fetchone()[0]

    def silent_clients(self, cutoff: float, min_queries: int):
        return self.db.execute(
            "SELECT ident, last_seen FROM client WHERE last_seen < ? AND queries >= ? AND silent_alerted = 0",
            (cutoff, min_queries),
        ).fetchall()

    def mark_silent(self, ident: str) -> None:
        self.db.execute("UPDATE client SET silent_alerted = 1 WHERE ident = ?", (ident,))

    # devices ------------------------------------------------------------------
    def known_device(self, hwaddr: str) -> bool:
        return self.db.execute("SELECT 1 FROM device WHERE hwaddr = ?", (hwaddr,)).fetchone() is not None

    def add_device(self, hwaddr: str, now: float) -> None:
        self.db.execute("INSERT OR IGNORE INTO device (hwaddr, first_seen) VALUES (?, ?)", (hwaddr, now))

    # dedup --------------------------------------------------------------------
    def suppress(self, key: str, now: float, seconds: float) -> bool:
        """True if key is inside its suppression window; otherwise opens a new window."""
        row = self.db.execute("SELECT until FROM dedup WHERE key = ?", (key,)).fetchone()
        if row and row[0] > now:
            return True
        self.db.execute(
            "INSERT INTO dedup (key, until) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET until = excluded.until",
            (key, now + seconds),
        )
        return False

    # telegram buttons ---------------------------------------------------------
    def add_action(self, payload: dict, now: float) -> str:
        """Store what a button does; its callback_data is "a:<id>" (Telegram allows 64 bytes)."""
        action_id = secrets.token_hex(6)
        self.db.execute("INSERT INTO action (id, payload, created) VALUES (?, ?, ?)",
                        (action_id, json.dumps(payload), now))
        return action_id

    def take_action(self, action_id: str, now: float) -> dict | None:
        """The button's payload, once: a second press, or one a day later, gets None."""
        row = self.db.execute("SELECT payload, created FROM action WHERE id = ?", (action_id,)).fetchone()
        if not row:
            return None
        self.db.execute("DELETE FROM action WHERE id = ?", (action_id,))
        return json.loads(row[0]) if now - row[1] <= ACTION_TTL else None

    def prune(self, now: float) -> None:
        self.db.execute("DELETE FROM dedup WHERE until < ?", (now,))
        self.db.execute("DELETE FROM action WHERE created < ?", (now - ACTION_TTL,))
