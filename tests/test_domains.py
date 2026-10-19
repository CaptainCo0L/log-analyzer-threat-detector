import pytest

from pihole_detector.domains import apex, looks_random, registrable_label, shannon_entropy, subdomain_part
from pihole_detector.intel import DomainSet


@pytest.mark.parametrize("domain, expected", [
    ("www.example.com", "example.com"),
    ("a.b.example.co.uk", "example.co.uk"),
    ("example.com.", "example.com"),
    ("WWW.Example.COM", "example.com"),
    # private PSL section is ignored on purpose: cloudfront customers share one apex
    ("d1x9k2q7zt.cloudfront.net", "cloudfront.net"),
    ("com", "com"),
    ("printer.lan", "printer.lan"),
])
def test_apex(domain, expected):
    assert apex(domain) == expected


def test_subdomain_and_label():
    assert subdomain_part("x.y.example.co.uk") == "x.y"
    assert subdomain_part("example.com") == ""
    assert registrable_label("www.example.co.uk") == "example"


def test_entropy_bounds():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0
    assert shannon_entropy("abcd") == pytest.approx(2.0)


@pytest.mark.parametrize("label", ["xkqjzvbwptrm", "a8f3k2q9z7x1", "qwrtzpsdfghk"])
def test_random_labels_flagged(label):
    assert looks_random(label)


@pytest.mark.parametrize("label", ["google", "facebook", "wikipedia", "stackoverflow",
                                   "microsoftonline", "xn--80ak6aa92e", "abcabcabcabc"])
def test_normal_labels_not_flagged(label):
    assert not looks_random(label)


def test_domainset_matches_parents_only():
    s = DomainSet(["bad.example"])
    assert s.match("bad.example") == "bad.example"
    assert s.match("x.y.bad.example") == "bad.example"
    assert s.match("notbad.example") is None
    assert s.match("example") is None
