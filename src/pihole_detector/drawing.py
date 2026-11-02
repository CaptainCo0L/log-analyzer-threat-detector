"""The picture cards: pushes, the digest and /status, drawn with Pillow. Pure, returns PNG bytes.

Telegram text can't have colour or font sizes, so these are images. Everything here may fail or be
missing (`Delivery.render` catches it), and every card has a plain-text version to fall back on.
Fonts are bundled so a card looks the same everywhere; both are under the SIL Open Font License.
"""

from __future__ import annotations

import io
import time
from collections import Counter
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

from .domains import apex
from .model import HIGH, LOW, MEDIUM, Alert
from .sinks import needs_attention, outcome, rule_title, when

WIDTH = 900
PAD = 40
GAP = 30
FONTS = Path(__file__).parent / "data" / "fonts"
WHITE = (255, 255, 255)
INK = (16, 24, 32)
COLOURS = {HIGH: (90, 26, 34), MEDIUM: (92, 62, 16), LOW: (33, 53, 74), "blocked": (18, 63, 47),
           "digest": (24, 47, 73), "ok": (20, 60, 51), "warn": (92, 62, 16), "down": (90, 26, 34)}
BARS = {HIGH: (255, 112, 118), MEDIUM: (245, 165, 36)}
TITLES = {"ti_match": "Known bad domain", "tunneling": "Possible data leak over DNS",
          "nxdomain_burst": "Random failed lookups", "new_device": "New device"}


@lru_cache(maxsize=32)
def display(size: int, weight: int = 700) -> ImageFont.FreeTypeFont:
    font = ImageFont.truetype(str(FONTS / "BricolageGrotesque.ttf"), size)
    font.set_variation_by_axes([min(size, 96), weight, 100])  # optical size, weight, width
    return font


@lru_cache(maxsize=32)
def body(size: int, weight: int = 500) -> ImageFont.FreeTypeFont:
    font = ImageFont.truetype(str(FONTS / "Figtree.ttf"), size)
    font.set_variation_by_axes([weight])
    return font


def _mix(colour: tuple, amount: float) -> tuple:
    """`colour` moved towards white."""
    return tuple(round(c + (255 - c) * amount) for c in colour)


def clip(text: str, font, width: float) -> str:
    """`text`, cut with an ellipsis if it would not fit on one line."""
    if font.getlength(text) <= width:
        return text
    while text and font.getlength(text + "…") > width:
        text = text[:-1]
    return text.rstrip() + "…"


def wrap(text: str, font, width: float, max_lines: int = 2) -> list[str]:
    """`text` broken at spaces. What's left after `max_lines` ends in an ellipsis on the last line."""
    lines: list[str] = []
    words = text.split()
    while words and len(lines) < max_lines:
        line = words.pop(0)
        while words and font.getlength(f"{line} {words[0]}") <= width:
            line = f"{line} {words.pop(0)}"
        lines.append(line)
    if words or (lines and font.getlength(lines[-1]) > width):
        lines[-1] = clip(" ".join([lines[-1], *words]) + " " * bool(words), font, width)
        if words and not lines[-1].endswith("…"):
            lines[-1] += "…"
    return lines


class Card:
    """A tall sheet drawn top to bottom, cropped to what was used."""

    def __init__(self, colour: tuple):
        self.colour = colour
        self.image = Image.new("RGB", (WIDTH, 1400), colour)
        self.draw = ImageDraw.Draw(self.image)
        self.y = PAD
        self.inner = WIDTH - 2 * PAD

    def top(self, left: str, right: str, pill: bool = True) -> None:
        font = body(26, 600)
        if pill:
            width = font.getlength(left) + 36
            self.draw.rounded_rectangle((PAD, self.y, PAD + width, self.y + 42), 21, fill=WHITE)
            self.draw.text((PAD + 18, self.y + 21), left, font=font, fill=INK, anchor="lm")
        else:
            self.draw.text((PAD, self.y + 21), left, font=font, fill=_mix(self.colour, 0.8), anchor="lm")
        self.draw.text((WIDTH - PAD, self.y + 21), right, font=body(26), fill=_mix(self.colour, 0.8), anchor="rm")
        self.y += 42 + GAP

    def headline(self, text: str) -> None:
        font = display(60)
        for line in wrap(text, font, self.inner):
            self.draw.text((PAD, self.y), line, font=font, fill=WHITE, anchor="lt")
            self.y += 68
        self.y += GAP - 8

    def line(self, text: str, size: int = 32, weight: int = 600, colour: tuple = WHITE) -> None:
        font = body(size, weight)
        for part in wrap(text, font, self.inner):
            self.draw.text((PAD, self.y), part, font=font, fill=colour, anchor="lt")
            self.y += size + 10
        self.y += GAP - 10

    def _node(self, box: tuple, names: list[str], details: list[str]) -> None:
        left, top, right, bottom = box
        self.draw.rounded_rectangle(box, 18, fill=_mix(self.colour, 0.11))
        y = top + 18
        for line in names:
            self.draw.text((left + 18, y), line, font=body(30, 700), fill=WHITE, anchor="lt")
            y += 36
        for line in details:
            self.draw.text((left + 18, y + 4), line, font=body(25), fill=_mix(self.colour, 0.8), anchor="lt")
            y += 31

    def flow(self, left: tuple[str, str], right: tuple[str, str], cut: bool) -> None:
        mid_left, mid_right = PAD + 330, PAD + 330 + 80
        room_left, room_right = mid_left - PAD - 36, WIDTH - PAD - mid_right - 36
        nodes = [(wrap(left[0], body(30, 700), room_left), wrap(left[1], body(25), room_left)),
                 (wrap(right[0], body(30, 700), room_right), wrap(right[1], body(25), room_right))]
        height = 44 + max(36 * len(names) + 31 * len(details) for names, details in nodes)
        self._node((PAD, self.y, mid_left, self.y + height), *nodes[0])
        self._node((mid_right, self.y, WIDTH - PAD, self.y + height), *nodes[1])
        y = self.y + height // 2
        if cut:
            centre = (mid_left + mid_right) // 2
            for x in (mid_left + 8, mid_right - 22):
                self.draw.line((x, y, x + 14, y), fill=WHITE, width=5)
            for dx in (-1, 1):
                self.draw.line((centre - 13, y - 13 * dx, centre + 13, y + 13 * dx), fill=WHITE, width=7)
        else:
            self.draw.line((mid_left + 10, y, mid_right - 26, y), fill=WHITE, width=6)
            tip = mid_right - 10
            self.draw.polygon([(tip, y), (tip - 20, y - 13), (tip - 20, y + 13)], fill=WHITE)
        self.y += height + GAP

    def counts(self, values: list[tuple[int, str]]) -> None:
        width = (self.inner - 2 * 14) // len(values)
        for i, (value, name) in enumerate(values):
            left = PAD + i * (width + 14)
            self.draw.rounded_rectangle((left, self.y, left + width, self.y + 118), 18, fill=_mix(self.colour, 0.09))
            self.draw.text((left + 20, self.y + 14), str(value), font=display(52), fill=WHITE, anchor="lt")
            self.draw.text((left + 20, self.y + 76), name, font=body(25), fill=_mix(self.colour, 0.8), anchor="lt")
        self.y += 118 + GAP

    def hours(self, records: list[dict]) -> None:
        count: Counter = Counter()
        worst: dict[int, str] = {}
        for r in records:
            hour = time.localtime(r["time"]).tm_hour
            count[hour] += 1
            if r["severity"] == HIGH or (r["severity"] == MEDIUM and worst.get(hour) != HIGH):
                worst[hour] = r["severity"]
        tallest = max(count.values(), default=1)
        width = self.inner / 24
        for hour in range(24):
            height = 8 + 92 * count[hour] / tallest if count[hour] else 5
            left = PAD + hour * width
            self.draw.rectangle((left, self.y + 100 - height, left + width - 5, self.y + 100),
                                fill=BARS.get(worst.get(hour, ""), _mix(self.colour, 0.3 if count[hour] else 0.16)))
        self.y += 112
        font = body(23)
        for hour in (0, 6, 12, 18, 24):
            anchor = "lt" if hour == 0 else "rt" if hour == 24 else "mt"
            self.draw.text((PAD + hour * width, self.y), f"{hour:02}", font=font, fill=_mix(self.colour, 0.72), anchor=anchor)
        self.y += 30 + GAP

    def rows(self, rows: list[tuple[str, str]]) -> None:
        strong, plain = body(29, 700), body(29)
        for name, value in rows:
            name = clip(name, strong, self.inner * 0.42)
            self.draw.text((PAD, self.y), name, font=strong, fill=WHITE, anchor="lt")
            shown = clip(value, plain, self.inner - strong.getlength(name) - 24)
            self.draw.text((WIDTH - PAD, self.y), shown, font=plain, fill=_mix(self.colour, 0.82), anchor="rt")
            self.y += 44
        self.y += GAP - 14

    def png(self) -> bytes:
        cropped = self.image.crop((0, 0, WIDTH, min(self.y - GAP + PAD, self.image.height)))
        out = io.BytesIO()
        cropped.save(out, format="PNG", optimize=True)
        return out.getvalue()


def _target(alert: Alert, blocked: bool) -> tuple[str, str]:
    """What the alert's device reached, for the right of the diagram."""
    ev = alert.evidence or {}
    domain = ev.get("matched") or (apex(alert.domain) if alert.domain else "")
    if blocked:
        return domain, "Blocked for everyone"
    if alert.rule == "ti_match":
        return domain, "On a threat list"
    if alert.rule == "tunneling":
        return domain, "Unusual lookups"
    if alert.rule == "nxdomain_burst":
        return "Random names", f"{ev.get('unique')} failed lookups"
    if alert.rule == "new_device":
        return "Your network", ev.get("vendor") or "Unknown vendor"
    return domain or "Your network", rule_title(alert.rule)


def alert_card(alert: Alert, blocked: bool = False) -> bytes:
    card = Card(COLOURS["blocked"] if blocked else COLOURS.get(alert.severity, COLOURS[LOW]))
    card.top("Blocked" if blocked else alert.severity.capitalize(), when(alert.time))
    card.headline(TITLES.get(alert.rule, rule_title(alert.rule)))
    device = alert.ips[0] if alert.ips else alert.mac
    card.flow((alert.label, device if device != alert.label else alert.mac), _target(alert, blocked), blocked)
    verdict = "Blocked, with all its subdomains." if blocked else outcome(alert)
    if verdict:
        card.line(verdict)
    return card.png()


def digest_card(records: list[dict], stats: dict, start: float, end: float) -> bytes:
    by_severity = Counter(r["severity"] for r in records)
    urgent = sorted((r for r in records if needs_attention(r)), key=lambda r: r["severity"] != HIGH)
    count = len(urgent)
    card = Card(COLOURS["digest"])
    card.top(f"{time.strftime('%A', time.localtime(end))} digest", f"{stats.get('queries', 0):,} lookups", pill=False)
    if count:
        card.headline(f"{count} thing{'' if count == 1 else 's'} to look at")
    else:
        card.headline(f"{by_severity[LOW]} low alert{'' if by_severity[LOW] == 1 else 's'}")
    if stats.get("api_failures"):
        card.line(f"{stats['api_failures']} failed polls", colour=BARS[MEDIUM])
    card.counts([(by_severity[HIGH], "High"), (by_severity[MEDIUM], "Medium"), (by_severity[LOW], "Low")])
    card.hours(records)
    if urgent:
        card.rows([(r.get("label", "?"), r.get("domain") or rule_title(r["rule"])) for r in urgent[:3]])
    return card.png()


def status_card(level: str, summary: str, rows: list[tuple[str, str]], moment: str) -> bytes:
    card = Card(COLOURS[level])
    card.top("Status", moment, pill=False)
    card.headline(summary)
    if rows:
        card.rows(rows)
    return card.png()
