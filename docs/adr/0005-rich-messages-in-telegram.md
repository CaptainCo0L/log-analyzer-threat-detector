# 5. Pushes, the digest and /status are rich messages, not pictures

Date: 2026-11-02 · Status: accepted, supersedes [ADR 0004](0004-picture-cards-in-telegram.md)

## Context

The picture cards worked, but the owner disliked having an image attached to every message, and each card
repeated facts already in its caption. Telegram's rich messages (Bot API 10.1) give headings, tables and folding
sections as text, and coloured buttons (Bot API 9.4) give colour without an image.

## Decision

`sendRichMessage` carries pushes, digests with alerts and `/status`, written in its HTML form. The drawing code,
fonts and Pillow are gone, so the detector is standard library only again. Short replies and health messages stay
ordinary text.

A press edits the message from the blocks Telegram reports for it. Those blocks can be sent back as they are,
which was tried on a real message before building on it, so nothing needs storing. The first block is the
heading, so a pushed alert can change state in place.

Link detection is off for anything naming a domain. Telegram otherwise turns domains and addresses into links,
and a bad domain must never be one tap away. `/status` names none, so it keeps it on and its /commands stay tappable.

## Consequences

- Every rich message keeps a plain-text twin in `sinks.py`, sent when Telegram refuses the rich one or
  `RICH_MESSAGES` is off. Both must say the same things.
- Rich messages can't be searched or copied quite like text: a table copies poorly in Telegram Desktop.
- Only Block is coloured, blue rather than red because it is safe and can be undone.
- Buttons on pictures sent before this change still work, and answer with a new message.
