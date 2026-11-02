"""The cards are pictures, so these check what a test can see: they open, they fit, and each state differs."""

import io

import pytest
from PIL import Image

from pihole_detector import drawing
from pihole_detector.model import Alert
from conftest import T0


def alert(rule="ti_match", label="Pixel 6", domain="login.evil-c2.example", severity="HIGH", **evidence):
    evidence.setdefault("matched", "evil-c2.example")
    evidence.setdefault("block", "sudo docker exec pihole pihole --wild evil-c2.example")
    return Alert(time=T0, severity=severity, rule=rule, label=label, domain=domain, message="m", evidence=evidence,
                 device="d", mac="02:00:00:00:00:30", ips=("192.0.2.30",))


def record(severity="MEDIUM", label="TV", domain="xk7qz9w2vb4m.com", rule="dga_single", t=0):
    return {"severity": severity, "rule": rule, "label": label, "domain": domain, "time": T0 + t, "evidence": {}}


def opened(png):
    image = Image.open(io.BytesIO(png))
    image.load()
    return image


def background(png):
    return opened(png).convert("RGB").getpixel((4, 4))


@pytest.mark.parametrize("make", [
    lambda: drawing.alert_card(alert()),
    lambda: drawing.alert_card(alert(), blocked=True),
    lambda: drawing.digest_card([record()], {"queries": 31204}, T0, T0 + 86400),
    lambda: drawing.status_card("ok", "All good", [("Pi-hole", "Up and blocking")], "14:02"),
], ids=["alert", "blocked", "digest", "status"])
def test_every_card_is_a_png_of_the_same_width(make):
    image = opened(make())
    assert image.format == "PNG" and image.width == drawing.WIDTH and 200 < image.height < 1400


def test_blocking_changes_the_cards_colour():
    assert background(drawing.alert_card(alert())) != background(drawing.alert_card(alert(), blocked=True))


def test_severity_sets_the_colour():
    assert background(drawing.alert_card(alert())) != background(drawing.alert_card(alert(severity="MEDIUM")))


@pytest.mark.parametrize("rule, evidence", [
    ("tunneling", {"reasons": ["50 unique subdomains"]}),
    ("nxdomain_burst", {"unique": 20, "samples": ["a.example"]}),
    ("new_device", {"vendor": "Acme"}),
    ("brand_new_rule", {}),
])
def test_every_rule_draws(rule, evidence):
    assert opened(drawing.alert_card(alert(rule, **evidence))).width == drawing.WIDTH


def test_a_very_long_name_and_domain_cannot_break_a_card():
    card = drawing.alert_card(alert(label="A device with a really very long name " * 8, domain="x" * 250 + ".example"))
    assert opened(card).height < 1400


def test_names_outside_latin_still_draw():
    assert opened(drawing.alert_card(alert(label="パソコン 🎮 Привет")))


def test_more_alerts_on_one_hour_draw_a_taller_bar():
    quiet = drawing.digest_card([record()], {}, T0, T0 + 86400)
    busy = drawing.digest_card([record() for _ in range(9)], {}, T0, T0 + 86400)
    assert quiet != busy


def test_a_digest_of_only_low_alerts_draws():
    assert opened(drawing.digest_card([record("LOW", domain="", rule="device_silent")], {}, T0, T0 + 86400))


def test_failed_polls_appear_on_the_digest():
    plain = drawing.digest_card([record()], {}, T0, T0 + 86400)
    assert opened(drawing.digest_card([record()], {"api_failures": 3}, T0, T0 + 86400)).height > opened(plain).height


@pytest.mark.parametrize("level", ["ok", "warn", "down"])
def test_status_levels_differ(level):
    colours = {background(drawing.status_card(name, "x", [], "14:02")) for name in ("ok", "warn", "down")}
    assert len(colours) == 3 and opened(drawing.status_card(level, "x", [("a", "b")], "14:02"))


def test_clip_shortens_with_an_ellipsis_and_only_when_needed():
    font = drawing.body(28, 500)
    assert drawing.clip("short", font, 400) == "short"
    cut = drawing.clip("x" * 200, font, 200)
    assert cut.endswith("…") and font.getlength(cut) <= 200


def test_wrap_keeps_within_the_width_and_the_line_limit():
    font = drawing.body(28, 500)
    lines = drawing.wrap("one two three four five six seven eight nine ten " * 5, font, 300, max_lines=2)
    assert len(lines) == 2 and all(font.getlength(line) <= 300 for line in lines) and lines[-1].endswith("…")
