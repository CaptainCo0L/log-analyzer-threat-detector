"""A message that changes as its buttons are pressed. Pure text and keyboard work, no I/O.

Each press comes with the message's own text and formatting, so nothing needs storing and a restart
loses nothing. Statuses are added after everything else, so the formatting's offsets stay valid.
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


def swap_row(rows: list[list[dict]], data: str, row: list[dict]) -> list[list[dict]]:
    """The keyboard with the row holding the pressed button replaced."""
    return [row if any(button.get("callback_data") == data for button in old) else old for old in rows]
