"""Every rich message has a plain-text twin (ADR 0005), and both must say the same things.

Each test renders both forms from one fully populated input and checks the facts a person acts on appear in
both, once the HTML is stripped. Wording and layout may differ; the facts may not.
"""

from pihole_detector.model import Alert
from pihole_detector.sinks import (StatusFacts, build_digest, format_push, format_status, rich_digest, rich_push,
                                   rich_status, rule_title, strip_html, when)
from conftest import T0

DAY = 86400


def both(rich: str, text: str) -> tuple[str, str]:
    return strip_html(rich), strip_html(text)


def missing(facts, rich: str, text: str) -> dict[str, list[str]]:
    r, t = both(rich, text)
    gaps = {"rich": [f for f in facts if f not in r], "text": [f for f in facts if f not in t]}
    return {form: gap for form, gap in gaps.items() if gap}


PUSH = Alert(time=T0, severity="HIGH", rule="ti_match", label="Kitchen iPad", domain="login.evil-c2.example",
             device="02:00:00:00:00:30", mac="02:00:00:00:00:30", ips=("192.0.2.30",), dedup="d", message="m",
             evidence={"matched": "evil-c2.example", "cname": "edge.cdn.example",
                       "previous_mac": "06:00:00:00:00:31", "block": "pihole deny --wild evil-c2.example"})


def test_a_push_and_its_twin_say_the_same_things():
    facts = ["Kitchen iPad", "login.evil-c2.example", "Pi-hole didn't block this lookup.",
             "pihole deny --wild evil-c2.example", "192.0.2.30", "02:00:00:00:00:30", "evil-c2.example",
             "edge.cdn.example", "06:00:00:00:00:31", when(T0), "ti_match"]
    assert missing(facts, rich_push(PUSH), format_push(PUSH)) == {}


def test_a_push_with_buttons_leaves_the_command_out_of_both():
    r, t = both(rich_push(PUSH, hint=False), format_push(PUSH, hint=False))
    assert "pihole deny" not in r and "pihole deny" not in t


def record(severity, rule, label, domain=None, **evidence) -> dict:
    return {"time": T0 - 3600, "severity": severity, "rule": rule, "label": label, "domain": domain,
            "evidence": evidence, "ips": ["192.0.2.40"], "mac": "02:00:00:00:00:40"}


DIGEST = [record("HIGH", "ti_match", "Kitchen iPad", "login.evil-c2.example"),
          record("MEDIUM", "beaconing", "AswinPC", "checkin.example", interval_s=60),
          record("LOW", "new_device", "Galaxy Tab")]
STATS = {"queries": 12345, "api_failures": 3}


def test_a_digest_and_its_twin_say_the_same_things():
    facts = ["Kitchen iPad", "AswinPC", "Galaxy Tab", rule_title("ti_match"), rule_title("beaconing"),
             rule_title("new_device"), "12,345", "3 failed polls", when(T0 - DAY),
             "login.evil-c2.example", "checkin.example"]
    assert missing(facts, rich_digest(DIGEST, STATS, T0 - DAY, T0), build_digest(DIGEST, STATS, T0 - DAY, T0)) == {}


def status(**kw) -> StatusFacts:
    facts = {"now": T0, "started": T0 - 7200, "blocking": {"blocking": "disabled", "timer": 300}, "error": "",
             "counts": {"HIGH": 2, "MEDIUM": 0, "LOW": 5}, "api_failures": 3, "queries": 12345,
             "last_digest": T0 - 5000, "next_digest": T0 + 3600, "mute_until": T0 + 1800, "quiet": "23:00-07:00",
             "quiet_now": False, "held": 4, "push_enabled": True, "rotation_sync": False, "nmap_enabled": True}
    return StatusFacts(**{**facts, **kw})


def test_a_status_and_its_twin_say_the_same_things():
    facts = ["disabled", "5 min", "2 high", "5 low", "3 failed polls", when(T0 + 1800), "23:00-07:00", "4 held",
             when(T0 + 3600), "2 h", "12,345", when(T0 - 5000), "/resume", "/unmute"]
    assert missing(facts, rich_status(status()), format_status(status())) == {}


def test_a_status_that_cant_reach_pihole_says_so_in_both():
    down = status(blocking=None, error="ApiError")
    assert missing(["Pi-hole is not reachable"], rich_status(down), format_status(down)) == {}


def test_a_digest_row_names_one_domain_and_counts_the_rest():
    many = [record("HIGH", "ti_match", "Kitchen iPad", d) for d in ("a.example", "b.example", "a.example", "c.example")]
    r = strip_html(rich_digest(many, STATS, T0 - DAY, T0))
    assert "×4" in r and "a.example +2 more" in r and "b.example" not in r
