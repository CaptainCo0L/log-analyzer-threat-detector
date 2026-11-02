"""A message that changes as its buttons are pressed. Pure text and keyboard work, no I/O.

Each press comes with the message's own text and formatting, or its blocks when it is a rich message, so
nothing needs storing and a restart loses nothing. Statuses are added after everything else, so the
formatting's offsets stay valid.
"""

from __future__ import annotations

BLOCK_STATUS = ("🛡", "↩️")
MUTE_STATUS = ("🔕", "🔔")
_STATUS = BLOCK_STATUS + MUTE_STATUS


def _is_status(line: str, family: tuple[str, ...], key: str = "") -> bool:
    return line.startswith(family) and key in line


def set_status(text: str, family: tuple[str, ...], key: str, status: str) -> str:
    """`text` with `status` as the latest word on `key` in its family, replacing the one before."""
    lines = text.split("\n")
    first = len(lines)  # statuses are the last lines, after a blank one
    while first > 0 and _is_status(lines[first - 1], _STATUS):
        first -= 1
    body, statuses = lines[:first], lines[first:]
    if not statuses or lines[first - 1] != "":
        body, statuses = lines, []
    kept = [line for line in statuses if not _is_status(line, family, key)]
    return "\n".join(body).rstrip() + "\n\n" + "\n".join([*kept, status])


def set_rich_status(blocks: list[dict], family: tuple[str, ...], key: str, status: str = "",
                    heading: str = "") -> list[dict]:
    """A rich message's blocks with `status` as the latest word on `key`, replacing the one before. `heading`
    replaces the first block's text, for when the message's state has changed. No `status` just clears it."""
    def stale(block: dict) -> bool:
        text = block.get("text")
        return block.get("type") == "paragraph" and isinstance(text, str) and _is_status(text, family, key)

    kept = [block for block in blocks if not stale(block)]
    if heading and kept:
        kept[0] = {**kept[0], "text": heading}
    return [*kept, {"type": "paragraph", "text": status}] if status else kept


def swap_row(rows: list[list[dict]], data: str, row: list[dict]) -> list[list[dict]]:
    """The keyboard with the row holding the pressed button replaced."""
    return [row if any(button.get("callback_data") == data for button in old) else old for old in rows]
