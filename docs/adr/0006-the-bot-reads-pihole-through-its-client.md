# 6. The bot reads Pi-hole through its client, with no wrapper module

Date: 2026-11-11 · Status: accepted

## Context

The architecture review of 2026-11-11 proposed a "Network" module between the bot and Pi-hole. It would own
the bot's reads (devices, Clients, groups, blocking state, queries) and device lookup, and Bot would only
parse commands and format replies.

Before building it, device lookup had already moved into `Directory.find`, which returns one `Found` per
device (ADR 0003). What was left were seven direct reads through `PiholeClient`, most of them a few lines of
error handling. Deleting a wrapper around them would only put those lines back where they are now, so it
fails the deletion test. Tests already cross the real seam: `FakePihole` fakes the whole `PiholeClient`
protocol.

## Decision

The bot keeps reading Pi-hole directly through `PiholeClient`. The seam is the client protocol, which has
two adapters: the real API in `source.py` and `FakePihole` in tests. No wrapper module goes on top.

Logic about devices goes into `Directory`. Writes keep going through ops and `PiholeChanges`.

## Consequences

- Each read in the bot handles its own failure, and it must say Pi-hole didn't answer rather than guess.
  `_membership` replaced a fallback that made every device read "no Clients entry".
- Revisit this if a second consumer, such as a web page, needs the same reads, or if one read gains real
  logic beyond its error handling.
