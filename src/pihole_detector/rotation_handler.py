"""What follows when a private MAC answers with a name: the one place a rotation is acted on.

A rotation is noticed when a new MAC joins and answers, and by the weekly discovery for one that was
asleep then. rotation.py decides; this module does what it decided.
"""

from __future__ import annotations

import logging

from .rotation import format_sync, is_private, plan_sync

log = logging.getLogger(__name__)


class RotationHandler:
    def __init__(self, cfg, state, directory, changes, delivery):
        self.cfg, self.state, self.directory = cfg, state, directory
        self.changes, self.delivery = changes, delivery

    def answered(self, mac: str, name: str, source: str, now: float, last_seen: dict[str, float]) -> str | None:
        """A MAC answered with this name. The device's previous MAC if that makes it a rotation, else None."""
        if not is_private(mac):
            return None
        self._sync(mac, name, source, now, last_seen)
        old = self.directory.previous_mac(mac, name, source)
        if old:
            self.state.link_device(mac, old)
        return old

    def _sync(self, mac: str, name: str, source: str, now: float, last_seen: dict[str, float]) -> None:
        """Move the device's Pi-hole Clients entry onto its new private MAC (see rotation.py). Every
        change is logged for clients-undo and sent to Telegram. A failure leaves the alert as it was."""
        api = self.changes.api
        if not (self.cfg.rotation_sync and api):
            return
        try:
            plan = plan_sync(mac, name, source, api.clients(), self.directory.names.entries,
                             last_seen, self.cfg.rotation_keep)
        except Exception:
            log.exception("rotation sync for %s: reading Pi-hole Clients failed", mac)
            return
        if not plan.add:
            if plan.reason != "already a Pi-hole client":
                log.info("rotation sync for %s (%s): nothing done, %s", mac, name, plan.reason)
            return
        try:
            deleted, error = self.changes.apply_sync(plan, name, now)
        except Exception:
            log.exception("rotation sync for %s: adding it to Pi-hole Clients failed", mac)
            return
        if error:
            log.warning("rotation sync for %s: removing an old MAC failed: %s", mac, error)
        log.info("rotation sync: %s added %s, removed %s", name, mac, [e.mac for e in deleted] or "none")
        try:
            groups = api.groups()
        except Exception:
            groups = {}
        undo = ([[self.delivery.button("↩️ Undo", {"kind": "undo_rotation", "time": now}, now)]]
                if self.cfg.bot_enabled else None)
        self.delivery.send(format_sync(name, plan.add, deleted, groups, error), undo)
