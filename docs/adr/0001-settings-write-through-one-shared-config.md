# 1. Settings change one shared Config; modules read it directly

Date: 2026-10-29 · Status: accepted

## Context

`/set` and `/unset` change thresholds and switches while the detector runs. The architecture review of
2026-10-28 proposed that every module read settings *through* a Settings module. Before this decision,
`/set` wrote straight onto the shared `Config` and also patched Telegram's private copy of
`push_cap_per_hour`. A value that some module copied at construction would silently go stale.

## Decision

`config.Settings` is the only writer: it applies the saved overrides at startup, and owns `set` and
`unset` (back to the value `.env` gave, captured before the overrides). Everything else keeps reading the
one shared `Config` (`ctx.cfg`, `self.cfg`) directly. **No module may keep its own copy of a SETTABLE
value**; read it from the Config each time (`Delivery` reads the push cap per push).

## Consequences

- No read-side seam: rules keep their plain `ctx.cfg.x` reads, and the change touched no rule.
- The "no copies" rule is a convention, not something the code enforces. Review new code that stores a
  SETTABLE value in `__init__`.
