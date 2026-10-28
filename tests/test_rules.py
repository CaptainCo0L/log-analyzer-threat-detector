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
    assert a.evidence["block"] == "sudo docker exec pihole pihole --wild evil-c2.example"
    assert PC_MAC in a.address


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


def test_digest_only_alerts_deduplicated_for_a_week(make_detector):
    # MEDIUM/LOW reach a human once a day, so a 6 h window just repeats them in the digest.
    det = make_detector(dedup_hours=6, digest_dedup_hours=168)
    assert det.process_query(q("dns.google", t=0))
    assert det.process_query(q("dns.google", t=2 * DAY)) == []
    assert det.process_query(q("dns.google", t=7 * DAY + 1))


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


def test_dga_single_ignores_blocked_queries(make_detector):
    # NULL blocking answers 0.0.0.0, which FTL reports as reply IP: blocked, not resolved.
    det = make_detector()
    assert det.process_query(q("fp.xkqjzvbwptrm.com", status="GRAVITY", reply="IP")) == []


def test_dga_single_ignores_apexes_many_clients_use(make_detector):
    det = make_detector(shared_clients=3)
    for ip in ("192.0.2.31", "192.0.2.32"):
        det.process_query(q("www.xkqjzvbwptrm.com", ip=ip))
    assert det.process_query(q("www.xkqjzvbwptrm.com", t=1)) == []   # third client: carrier/SDK infra


def test_dga_single_ignores_long_established_relationship(make_detector):
    det = make_detector(learning_days=7)
    det.process_query(q("www.xkqjzvbwptrm.com", t=0))
    assert det.process_query(q("www.xkqjzvbwptrm.com", t=8 * DAY)) == []


def test_dga_single_still_fires_while_the_client_is_learning(make_detector):
    det = make_detector(learning_days=7)
    det.process_query(q("example.com", t=0))
    assert rules_of(det.process_query(q("c.xkqjzvbwptrm.online", t=3 * DAY))) == ["dga_single"]


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
def beacon(det, n, interval, jitter=(), domain="checkin.c2.example", start=8 * DAY, **kw):
    """Beacon from a client already past its learning week (it first appears at t=0)."""
    det.process_query(q("warmup.example", t=0, ip=kw.get("ip", PC_IP)))
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
    det.process_query(q("warmup.example", t=0))
    out = []
    for i in range(11):
        out += det.process_query(q("pair.c2.example", t=8 * DAY + i * 60))
        out += det.process_query(q("pair.c2.example", t=8 * DAY + i * 60 + 0.01, qtype="AAAA"))
    assert rules_of(out).count("beaconing") == 1


def test_beaconing_skips_widely_used_domains(make_detector):
    det = make_detector(beacon_min_hits=10)
    for n, ip in enumerate(["192.0.2.31", "192.0.2.32", "192.0.2.33"]):
        det.process_query(q("connectivity.example", t=n, ip=ip))
    assert beacon(det, 12, 60.0, domain="connectivity.example", start=8 * DAY + 10) == []


def test_beaconing_skips_long_established_relationship(make_detector):
    det = make_detector(beacon_min_hits=10, learning_days=7)
    det.process_query(q("mqtt.vendor-cloud.example", t=0, ip=IOT_IP))
    assert beacon(det, 12, 60.0, domain="mqtt.vendor-cloud.example", start=8 * DAY, ip=IOT_IP) == []
    assert len(beacon(det, 12, 60.0, domain="new.c2.example", start=8 * DAY, ip=IOT_IP)) == 1


def test_beaconing_quiet_during_the_clients_learning_week(make_detector):
    # Live cold start: the fridge's hourly vendor heartbeat alerted until its first week was over.
    det = make_detector(beacon_min_hits=10, learning_days=7)
    assert [a for a in (det.process_query(q("hb.vendor.example", t=i * 3600, ip=IOT_IP)) for i in range(15))
            if a] == []
    assert beacon(det, 12, 3500.0, domain="hb.vendor.example", start=8 * DAY, ip=IOT_IP) == []


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
    assert IOT_MAC in alerts[0].address


def test_iot_off_baseline_skips_blocked_queries(make_detector):
    # live 2026-10-24: Sony TV -> browser-intake-us5-datadoghq.com, status GRAVITY; Pi-hole already stopped it
    det = make_detector(learning_days=7)
    det.process_query(q("vendor-cloud.example", t=0, ip=IOT_IP))
    assert det.process_query(q("telemetry.example", t=8 * DAY, ip=IOT_IP, status="GRAVITY")) == []


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


IPAD_OLD, IPAD_NEW = "02:00:00:00:00:30", "06:00:00:00:00:31"


def test_new_private_mac_answering_with_a_known_name_is_a_rotation(make_detector):
    # live 2026-10-24: the iPad came back on a new private MAC and raised a HIGH new_device
    det = make_detector()
    det.names.update({IPAD_OLD: ("Aswins-iPad", "mDNS")}, T0)
    calls = []
    det.probe = lambda ips, wait: calls.append(ips) or {"192.0.2.31": {"mDNS": "aswins-ipad"}}
    new = Device(hwaddr=IPAD_NEW, ips=("192.0.2.31", "fe80::1"), first_seen=T0)
    alerts = det.process_devices([new], T0 + 100)
    assert calls == [["192.0.2.31"]]  # IPv4 only, just this device
    a = alerts[0]
    assert a.rule == "new_device" and a.severity == "LOW" and det.telegram.messages == []
    assert a.client == "aswins-ipad" and a.evidence["previous_mac"] == IPAD_OLD
    assert "new private Wi-Fi MAC" in a.message
    assert det.names.name(IPAD_NEW) == "aswins-ipad"  # saved, so later alerts carry the name


def test_new_device_stays_high_when_name_unknown_or_mac_is_burned_in(make_detector):
    det = make_detector()
    det.names.update({IPAD_OLD: ("Aswins-iPad", "mDNS")}, T0)
    det.probe = lambda ips, wait: {"192.0.2.31": {"mDNS": "someone-else"}, "192.0.2.32": {"mDNS": "Aswins-iPad"}}
    stranger = Device(hwaddr=IPAD_NEW, ips=("192.0.2.31",), first_seen=T0)
    # a universally administered (burned-in) MAC never rotates, whatever name it claims
    burned_in = Device(hwaddr="00:11:22:33:44:55", ips=("192.0.2.32",), first_seen=T0)
    alerts = det.process_devices([stranger, burned_in], T0 + 100)
    assert [a.severity for a in alerts] == ["HIGH", "HIGH"]


def test_new_device_probe_failure_keeps_high(make_detector):
    det = make_detector()

    def broken(ips, wait):
        raise OSError("network unreachable")
    det.probe = broken
    alerts = det.process_devices([Device(hwaddr=IPAD_NEW, ips=("192.0.2.31",), first_seen=T0)], T0 + 100)
    assert [a.severity for a in alerts] == ["HIGH"]


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
    assert len(det.telegram.messages) == 1 and "Malware / phishing domain" in det.telegram.messages[0]
    assert "pihole --wild evil-c2.example" in det.telegram.messages[0]


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
    assert "Encrypted DNS in use" in det.telegram.messages[-1]
    assert det.maybe_digest(morning + 24 * 3600) is False        # same day again


def test_digest_and_hourly_stats_are_logged(make_detector, monkeypatch, caplog):
    import logging
    import time as _time
    monkeypatch.setattr(_time, "localtime", _time.gmtime)
    caplog.set_level(logging.INFO, logger="pihole_detector")
    det = make_detector(digest_hour=9)
    det.process_query(q("example.com"))
    det.tick(T0 + 3600)
    assert "stats: 1 queries" in caplog.text
    det.maybe_digest(T0 + 3600, force=True)
    assert "digest sent" in caplog.text


def test_every_alert_written_to_jsonl(make_detector):
    det = make_detector()
    det.process_query(q("evil-c2.example"))
    det.process_query(q("dns.google", t=1))
    assert [r["rule"] for r in det.alert_log.read()] == ["ti_match", "doh_bypass"]


def test_label_uses_pihole_client_comment(make_detector):
    det = make_detector()
    det.intel.names = {PC_MAC: "AswinPC"}
    a = det.process_query(q("evil-c2.example"))[0]
    assert a.client == "AswinPC" and a.address == f"{PC_IP} · {PC_MAC}"
    unnamed = det.process_query(q("evil-c2.example", ip="192.0.2.77"))[0]
    assert unnamed.client == "192.0.2.77"
