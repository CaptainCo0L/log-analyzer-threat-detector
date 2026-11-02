# 4. Pushes, the digest and /status are picture cards, drawn with Pillow

Date: 2026-11-02 · Status: superseded by [ADR 0005](0005-rich-messages-in-telegram.md)

## Context

Telegram text has no colour, font sizes or backgrounds, so rewording and reordering messages could not make
them look different. Three routes were mocked up: sharper text (aligned tables, little visual change), picture
cards, and a Mini App (a web dashboard inside Telegram). The Mini App needs a web server on a public HTTPS
address, and the detector deliberately has no open port. The owner chose picture cards.

## Decision

The detector stops being standard library only: `drawing.py` draws cards with Pillow, using two fonts bundled
under `data/fonts`. Every card still has its plain-text message, sent when `IMAGE_CARDS` is off, when drawing
fails, or when Telegram refuses the photo. Nothing depends on a card arriving.

Quiet digests stay one line of text: a picture of nothing happening would ask for more attention than it deserves.

## Consequences

- Pillow is a pinned dependency in `pyproject.toml`, `requirements-dev.txt` and the Dockerfile. Change all three together.
- Only a card's caption can be copied or searched, so facts that aren't on the card stay in the caption's fold.
- A Block button carries the alert, so pressing it can redraw the card. Captions hold 1024 characters, not 4096.
- Device names outside the bundled fonts' Latin coverage draw as empty boxes on the card. The caption shows them correctly.
- `IMAGE_CARDS=false`, or `/set IMAGE_CARDS false`, goes back to text without a deploy.
