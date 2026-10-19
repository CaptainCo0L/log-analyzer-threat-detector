from pihole_detector.model import Device
from conftest import IOT_IP, IOT_MAC, PC_IP, PC_MAC, T0, q, rules_of

DAY = 86400


# ti_match ---------------------------------------------------------------------
def test_ti_match_on_subdomain_and_reports_unblocked(make_detector):
    det = make_detector()
    alerts = det.process_query(q("beacon.evil-c2.example"))
    assert rules_of(alerts) == ["ti_match"]
    a = alerts[0]
    assert a.severity == "HIGH"
    assert "NOT blocked" in a.message
    assert a.evidence["block"] == "sudo docker exec pihole pihole deny evil-c2.example"
    assert PC_MAC in a.client


def test_ti_match_blocked_query_has_no_block_hint(make_detector):
    det = make_detector()
    a = det.process_query(q("evil-c2.example", status="GRAVITY", reply="IP"))[0]
    assert "(blocked)" in a.message and a.evidence["block"] is None


def test_ti_match_via_cname(make_detector):
    det = make_detector()
    assert "ti_match" in rules_of(det.process_query(q("innocent.example", cname="x.evil-c2.example")))


def test_ti_no_match_for_lookalike(make_detector):
    det = make_detector()
    assert det.process_query(q("notevil-c2.example")) == []


def test_ti_alert_deduplicated_then_reopens_after_window(make_detector):
    det = make_detector(dedup_hours=6)
    assert det.process_query(q("evil-c2.example", t=0))
    assert det.process_query(q("evil-c2.example", t=60)) == []
    assert det.process_query(q("evil-c2.example", t=6 * 3600 + 1))


# doh_bypass -------------------------------------------------------------------
def test_doh_bypass(make_detector):
    det = make_detector()
    alerts = det.process_query(q("chrome.cloudflare-dns.com"))
    assert rules_of(alerts) == ["doh_bypass"] and alerts[0].severity == "MEDIUM"
    assert det.process_query(q("cloudflare.com")) == []


# dga_single -------------------------------------------------------------------
def test_dga_single_flags_random_registrable_label(make_detector):
    det = make_detector()
    assert rules_of(det.process_query(q("www.xkqjzvbwptrm.com"))) == ["dga_single"]


def test_dga_ignores_normal_cdn_and_single_label(make_detector):
    det = make_detector()
    assert det.process_query(q("d1x9k2q7zt8w.cloudfront.net")) == []   # random part is not the registrable label
    assert det.process_query(q("qwrtzpsdfghk", reply="NXDOMAIN")) == []  # Chrome intranet-redirect probe
    assert det.process_query(q("en.wikipedia.org")) == []


def test_dga_single_needs_a_positive_answer(make_detector):
    det = make_detector()
    # FTL leaves a retransmitted duplicate at UNKNOWN forever; that is not "resolved"
    assert det.process_query(q("www.xkqjzvbwptrm.com", reply="UNKNOWN")) == []
    assert det.process_query(q("www.xkqjzvbwptrm.com", reply="NXDOMAIN")) == []
    assert rules_of(det.process_query(q("www.xkqjzvbwptrm.com", reply="CNAME"))) == ["dga_single"]


# nxdomain_burst ---------------------------------------------------------------
def _dga_labels(n=30, seed=7):
    import random
    import string
    from pihole_detector.domains import looks_random
    rng = random.Random(seed)
    out = []
    while len(out) < n:
        label = "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(12))
        if looks_random(label, min_len=8):
            out.append(label)
    return out


RANDOM = _dga_labels()


def burst(det, n, spacing=5.0, start=0.0):
    out = []
    for i in range(n):
        out += det.process_query(q(f"{RANDOM[i]}.com", t=start + i * spacing, reply="NXDOMAIN"))
    return [a for a in out if a.rule == "nxdomain_burst"]


def test_nxdomain_burst_fires_at_threshold(make_detector):
    det = make_detector(nxdomain_threshold=20)
    assert burst(det, 19) == []
    det = make_detector(nxdomain_threshold=20)
    hits = burst(det, 21)
    assert len(hits) == 1 and hits[0].severity == "HIGH"   # per-client dedup: one alert, not two


def test_nxdomain_burst_respects_window(make_detector):
    det = make_detector(nxdomain_threshold=20, nxdomain_window=300)
    assert burst(det, 22, spacing=20.0) == []   # 22 names spread over 7 min, never 20 inside 5 min


def test_nxdomain_burst_ignores_resolved_and_repeats(make_detector):
    det = make_detector(nxdomain_threshold=5)
    for i in range(10):
        det.process_query(q(f"{RANDOM[i]}.com", t=i, reply="IP"))
        assert "nxdomain_burst" not in rules_of(det.process_query(q("xkqjzvbwpt.com", t=i + 0.5, reply="NXDOMAIN")))


# tunneling --------------------------------------------------------------------
def test_tunneling_unique_subdomains(make_detector):
    det = make_detector(tunnel_unique_subdomains=50)
    rules = []
    for i in range(50):
        rules += rules_of(det.process_query(q(f"c{i:04d}.exfil.example", t=i)))
    assert rules.count("tunneling") == 1


def test_tunneling_below_threshold_and_noisy_apex(make_detector):
    det = make_detector(tunnel_unique_subdomains=50)
    for i in range(49):
        assert "tunneling" not in rules_of(det.process_query(q(f"c{i:04d}.exfil.example", t=i)))
    for i in range(80):
        assert "tunneling" not in rules_of(det.process_query(q(f"rr{i}---sn-abc.googlevideo.com", t=i)))


def test_tunneling_long_labels_and_txt(make_detector):
    det = make_detector(tunnel_long_label_count=3, tunnel_txt_count=1000)
    label = "a" * 45
    found = []
    for i in range(3):
        found += rules_of(det.process_query(q(f"{label}{i}.t.example", t=i)))
    assert "tunneling" in found
    det = make_detector(tunnel_txt_count=5)
    found = []
    for i in range(5):
        found += rules_of(det.process_query(q("cmd.t.example", t=i * 3, qtype="TXT")))
    assert "tunneling" in found


def test_tunneling_window_expires(make_detector):
    det = make_detector(tunnel_unique_subdomains=10, tunnel_window=600)
    for i in range(20):
        assert "tunneling" not in rules_of(det.process_query(q(f"s{i}.slow.example", t=i * 120)))


# beaconing --------------------------------------------------------------------
def beacon(det, n, interval, jitter=(), domain="checkin.c2.example", start=0.0, **kw):
    out = []
    for i in range(n):
        offset = jitter[i % len(jitter)] if jitter else 0
        out += det.process_query(q(domain, t=start + i * interval + offset, **kw))
    return [a for a in out if a.rule == "beaconing"]


def test_beaconing_regular_interval(make_detector):
    det = make_detector(beacon_min_hits=10)
    hits = beacon(det, 11, 60.0)
    assert len(hits) == 1 and "every ~60s" in hits[0].message


def test_beaconing_needs_enough_hits(make_detector):
    det = make_detector(beacon_min_hits=10)
    assert beacon(det, 10, 60.0) == []


def test_beaconing_ignores_jittery_blocked_and_too_fast(make_detector):
    det = make_detector(beacon_min_hits=10)
    assert beacon(det, 15, 60.0, jitter=(0, 25, -20, 10, -25)) == []
    assert beacon(det, 15, 60.0, domain="ads.example", status="GRAVITY") == []
    assert beacon(det, 15, 5.0, domain="fast.example") == []   # below min interval


def test_beaconing_collapses_a_aaaa_pairs(make_detector):
    det = make_detector(beacon_min_hits=10)
    out = []
    for i in range(11):
        out += det.process_query(q("pair.c2.example", t=i * 60))
        out += det.process_query(q("pair.c2.example", t=i * 60 + 0.01, qtype="AAAA"))
    assert rules_of(out).count("beaconing") == 1


def test_beaconing_skips_widely_used_domains(make_detector):
    det = make_detector(beacon_min_hits=10)
    for n, ip in enumerate(["192.0.2.31", "192.0.2.32", "192.0.2.33"]):
        det.process_query(q("connectivity.example", t=n, ip=ip))
    assert beacon(det, 12, 60.0, domain="connectivity.example", start=10) == []


def test_beaconing_skips_long_established_relationship(make_detector):
    det = make_detector(beacon_min_hits=10, learning_days=7)
    det.process_query(q("mqtt.vendor-cloud.example", t=0, ip=IOT_IP))
    assert beacon(det, 12, 60.0, domain="mqtt.vendor-cloud.example", start=8 * DAY, ip=IOT_IP) == []
    assert len(beacon(det, 12, 60.0, domain="new.c2.example", start=8 * DAY, ip=IOT_IP)) == 1


# iot_off_baseline -----------------------------------------------------------------
def test_iot_off_baseline_only_after_learning(make_detector):
    det = make_detector(learning_days=7)
    assert det.process_query(q("vendor-cloud.example", t=0, ip=IOT_IP)) == []
    # new apex during learning: silent, but learned
    assert det.process_query(q("firmware.example", t=3 * DAY, ip=IOT_IP)) == []
    # after learning: known apexes stay quiet, a new one alerts
    assert det.process_query(q("api.vendor-cloud.example", t=8 * DAY, ip=IOT_IP)) == []
    alerts = det.process_query(q("strange-host.example", t=8 * DAY, ip=IOT_IP))
    assert rules_of(alerts) == ["iot_off_baseline"]
    assert IOT_MAC in alerts[0].client


def test_iot_rule_ignores_non_iot_clients(make_detector):
    det = make_detector(learning_days=7)
    det.process_query(q("a.example", t=0, ip=PC_IP))
    assert det.process_query(q("brand-new.example", t=8 * DAY, ip=PC_IP)) == []


# devices ----------------------------------------------------------------------------
def test_new_device_quiet_on_first_snapshot_then_alerts(make_detector):
    det = make_detector()   # factory already sent the first (quiet) snapshot
    new = Device(hwaddr="02:00:00:00:00:99", ips=("192.0.2.99",), first_seen=T0, vendor="Acme")
    placeholder = Device(hwaddr="ip-192.0.2.98", ips=("192.0.2.98",), first_seen=T0)
    alerts = det.process_devices([new, placeholder], T0 + 100)
    assert rules_of(alerts) == ["new_device"] and alerts[0].severity == "HIGH"
    assert det.process_devices([new], T0 + 200) == []


def test_device_silent_after_24h_once(make_detector):
    det = make_detector(silent_hours=24, silent_min_queries=3)
    for i in range(3):
        det.process_query(q("example.com", t=i))
    assert [a for a in det.tick(T0 + 23 * 3600) if a.rule == "device_silent"] == []
    det._last_prune = 0
    silent = [a for a in det.tick(T0 + 25 * 3600) if a.rule == "device_silent"]
    assert len(silent) == 1 and silent[0].severity == "LOW"
    det._last_prune = 0
    assert [a for a in det.tick(T0 + 30 * 3600) if a.rule == "device_silent"] == []


# routing ------------------------------------------------------------------------------
def test_high_alerts_pushed_only_when_enabled(make_detector):
    det = make_detector(push_enabled=False)
    det.process_query(q("evil-c2.example"))
    assert det.telegram.messages == []
    det = make_detector(push_enabled=True)
    det.process_query(q("evil-c2.example"))
    det.process_query(q("dns.google"))   # MEDIUM: digest only
    assert len(det.telegram.messages) == 1 and "ti_match" in det.telegram.messages[0]
    assert "To block:" in det.telegram.messages[0]


def test_digest_not_on_first_run_then_once_per_day(make_detector, monkeypatch):
    import time as _time
    monkeypatch.setattr(_time, "localtime", _time.gmtime)   # treat the clock as UTC
    det = make_detector(digest_hour=9)
    midnight = 1_760_400_000.0                 # 00:00 UTC
    assert midnight % 86400 == 0
    morning = midnight + 10 * 3600             # 10:00
    assert det.maybe_digest(morning) is False   # first run opens the window only
    det.process_query(q("dns.google", t=morning - T0 + 60))
    assert det.maybe_digest(morning + 3600) is False             # 11:00, day one already counted
    assert det.maybe_digest(morning + 22 * 3600) is False        # 08:00 next day: not yet
    assert det.maybe_digest(morning + 23 * 3600) is True         # 09:00 next day
    assert "doh_bypass" in det.telegram.messages[-1]
    assert det.maybe_digest(morning + 24 * 3600) is False        # same day again


def test_every_alert_written_to_jsonl(make_detector):
    det = make_detector()
    det.process_query(q("evil-c2.example"))
    det.process_query(q("dns.google", t=1))
    assert [r["rule"] for r in det.jsonl.since(0)] == ["ti_match", "doh_bypass"]
