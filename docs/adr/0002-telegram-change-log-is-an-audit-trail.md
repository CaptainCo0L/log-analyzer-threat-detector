# 2. The Telegram change log is an audit trail, not an undo source

Date: 2026-10-29 · Status: accepted

## Context

Every change the bot makes to Pi-hole is logged to `data/pihole_changes.jsonl`. Undo works through the
inverse ops stored in each reply's Undo button, which expire with the button. The architecture review
proposed a `history` interface and undoing Telegram changes from the CLI.

## Decision

The log stays write-only for the code: a record of what was done, for the owner to read. There is no
`history` method or CLI undo until something needs them. Rotation sync is different: its log
(`client_changes.jsonl`) *is* read, by `clients-undo` and the Undo button, and is never rolled over
yearly, so last year's changes stay undoable.

## Consequences

- An expired Undo button means undoing by hand (or with the matching opposite command, e.g. `/unblock`).
- Adding CLI undo later means writing the inverse ops into each log record first.
