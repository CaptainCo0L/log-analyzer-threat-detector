"""A pushed alert leads with what happened; the technical facts wait in an expandable quote."""

import re

import pytest

from conftest import T0
from pihole_detector.model import Alert
from pihole_detector.sinks import format_push

MAC = "02:00:00:00:00:30"
BLOCK = "sudo docker exec pihole pihole --wild evil.example"


def push(rule="ti_match", label="Pixel", domain="login.evil.example", **evidence):
    return Alert(time=T0, severity="HIGH", rule=rule, label=label, domain=domain, message="m",
                 evidence=evidence, device=MAC, mac=MAC, ips=("192.0.2.30",))


def visible(text):
    """What shows before the owner expands anything."""
    return re.sub(r"<blockquote expandable>.*?</blockquote>", "", text, flags=re.S)


def details(text):
    return re.search(r"<blockquote expandable>(.*?)</blockquote>", text, flags=re.S).group(1)


@pytest.mark.parametrize("alert, lead", [
    (push(block=BLOCK, matched="evil.example"), "Pixel looked up a known bad domain"),
    (push("tunneling", domain="evil.example", reasons=["50 unique subdomains"]), "Pixel may be sending data out through DNS"),
    (push("nxdomain_burst", domain="", unique=20, samples=["a.example"]), "Pixel is failing on lots of random domains"),
    (push("new_device", domain="", vendor="Acme"), "New device on your network: Pixel"),
])
def test_the_first_line_says_who_did_what(alert, lead):
    assert format_push(alert, hint=False).split("\n")[0] == f"🔴 <b>{lead}</b>"


def test_the_domain_and_the_outcome_come_right_after():
    lines = format_push(push(block=BLOCK, matched="evil.example"), hint=False).split("\n")
    assert lines[1] == "<code>login.evil.example</code>"
    assert lines[2] == "It wasn't blocked, so the lookup went through."


def test_a_blocked_lookup_says_pihole_stopped_it():
    assert "Pi-hole blocked it." in visible(format_push(push(block=None, matched="evil.example"), hint=False))


def test_tunneling_and_bursts_say_how_much_at_a_glance():
    assert "50 unique subdomains in 10 min." in visible(format_push(
        push("tunneling", reasons=["50 unique subdomains"]), hint=False))
    assert "20 failed lookups in 5 min." in visible(format_push(
        push("nxdomain_burst", domain="", unique=20, samples=["a.example"]), hint=False))


def test_technical_facts_wait_in_the_expandable_quote():
    text = format_push(push(block=BLOCK, matched="evil.example", cname="cdn.evil.example"), hint=False)
    for fact in ("192.0.2.30", MAC, "ti_match", "HIGH"):
        assert fact not in visible(text) and fact in details(text)
    assert "List entry: evil.example" in details(text) and "cdn.evil.example" in details(text)
    assert "threat-intelligence list" in details(text)   # what it means is one tap away


def test_a_burst_keeps_its_samples_in_the_details():
    assert "a.example" in details(format_push(push("nxdomain_burst", domain="", unique=20, samples=["a.example"])))


def test_a_new_device_says_who_made_it():
    assert "Made by Acme." in visible(format_push(push("new_device", domain="", vendor="Acme"), hint=False))
    assert "Unknown vendor." in visible(format_push(push("new_device", domain=""), hint=False))


def test_a_rule_without_its_own_wording_still_reads_sensibly():
    alert = Alert(time=T0, severity="MEDIUM", rule="brand_new", label="TV", domain="", message="m")
    assert format_push(alert).split("\n")[0] == "🟠 <b>TV: brand_new</b>"


def test_without_buttons_the_block_command_stays_in_view():
    text = format_push(push(block=BLOCK, matched="evil.example"), hint=True)
    assert f"<code>{BLOCK}</code>" in visible(text)


def test_with_buttons_the_block_command_is_left_to_them():
    assert BLOCK not in format_push(push(block=BLOCK, matched="evil.example"), hint=False)


def test_names_and_domains_cannot_break_the_html():
    text = format_push(push(label="<b>x", domain="a<b>.example", block=BLOCK, matched="<i>"), hint=False)
    assert "&lt;b&gt;x" in text and "a&lt;b&gt;.example" in text and "&lt;i&gt;" in text


def test_a_label_that_is_the_ip_is_not_repeated():
    assert details(format_push(push(label="192.0.2.30", block=BLOCK, matched="x"), hint=False)).count("192.0.2.30") == 0
