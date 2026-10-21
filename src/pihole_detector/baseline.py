"""How familiar a client -> apex relationship is: the one question the baseline rules share.

Stages, from the client's point of view:
- LEARNING: the client itself is younger than the learning period, so its baseline is still forming.
- KNOWN: the apex was learned during the client's learning period, or the relationship is older
  than the learning period.
- NEW: everything else - the client is established and this apex appeared after its learning week.

`shared` is separate: an apex in many clients' baselines is platform or carrier infrastructure
(OS checks, SDKs, Wi-Fi calling), not one host's anomaly.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import Config
from .state import State

LEARNING, KNOWN, NEW = "LEARNING", "KNOWN", "NEW"


@dataclass(frozen=True)
class Familiarity:
    stage: str
    shared: bool


class Baseline:
    def __init__(self, state: State, cfg: Config):
        self.state = state
        self.cfg = cfg

    def familiarity(self, ident: str, apex: str, now: float) -> Familiarity:
        learning = self.cfg.learning_days * 86400
        shared = self.state.apex_prevalence(apex) >= self.cfg.shared_clients
        client_first = self.state.client_first_seen(ident)
        if client_first is None or now - client_first < learning:
            return Familiarity(LEARNING, shared)
        apex_first = self.state.domain_first_seen(ident, apex)
        if apex_first is None:
            apex_first = now
        if apex_first < client_first + learning or now - apex_first >= learning:
            return Familiarity(KNOWN, shared)
        return Familiarity(NEW, shared)
