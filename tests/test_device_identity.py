"""A device stays one device across a rotation: what the detector knows about it follows it."""

from conftest import T0, q, rules_of
from pihole_detector.model import Device
from pihole_detector.rules.devices import silent_devices

DAY = 86400
OLD, NEW, THIRD = "02:00:00:00:00:30", "06:00:00:00:00:31", "0a:00:00:00:00:32"
OLD_IP, NEW_IP, THIRD_IP = "192.0.2.30", "192.0.2.31", "192.0.2.32"
LATER = 10 * DAY  # past the seven-day learning period


def settled(make_detector, **cfg):
    """A device past its learning period, with the name it gave over mDNS saved."""
    det = make_detector(**cfg)
    det.directory.names.update({OLD: ("Aswins-iPad", "mDNS")}, T0)
    det.process_devices([Device(hwaddr=OLD, ips=(OLD_IP,), first_seen=T0)], T0)
    det.process_query(q("usual.example", t=0, ip=OLD_IP))
    det.process_query(q("usual.example", t=LATER, ip=OLD_IP))
    return det


def rotate(det, mac=NEW, ip=NEW_IP, t=LATER + 100, source="mDNS"):
    det.probe = lambda ips, wait, **_: {ip: {source: "Aswins-iPad"}}
    det.process_devices([Device(hwaddr=mac, ips=(ip,), first_seen=T0 + t, last_query=T0 + t)], T0 + t)


def test_a_rotated_device_keeps_its_baseline(make_detector):
    det = settled(make_detector, iot=(NEW,))  # the IoT group lists the MAC in use, not the old one
    rotate(det)
    assert rules_of(det.process_query(q("usual.example", t=LATER + 200, ip=NEW_IP))) == []
    assert rules_of(det.process_query(q("fresh.example", t=LATER + 300, ip=NEW_IP))) == ["iot_off_baseline"]


def test_an_iot_client_listed_by_ip_still_counts_with_no_mac_known(make_detector):
    det = make_detector(iot=("192.0.2.77",))
    det.process_query(q("usual.example", t=0, ip="192.0.2.77"))
    assert rules_of(det.process_query(q("fresh.example", t=LATER, ip="192.0.2.77"))) == ["iot_off_baseline"]


def test_a_mute_follows_the_device(make_detector):
    det = settled(make_detector, push_enabled=True)
    det.delivery.mute("ti_match", OLD, T0 + LATER + DAY)
    rotate(det)
    pushes = len(det.telegram.messages)
    assert rules_of(det.process_query(q("evil-c2.example", t=LATER + 200, ip=NEW_IP))) == ["ti_match"]
    assert len(det.telegram.messages) == pushes


def test_an_alert_deduplicated_for_the_device_stays_so_on_its_new_mac(make_detector):
    det = settled(make_detector)
    assert rules_of(det.process_query(q("evil-c2.example", t=LATER + 50, ip=OLD_IP))) == ["ti_match"]
    rotate(det)
    assert rules_of(det.process_query(q("evil-c2.example", t=LATER + 200, ip=NEW_IP))) == []


def test_the_mac_it_left_does_not_raise_a_false_silence(make_detector):
    det = settled(make_detector, silent_min_queries=2)
    rotate(det)
    det.process_query(q("usual.example", t=LATER + 2 * DAY, ip=NEW_IP))
    assert silent_devices(det.ctx, T0 + LATER + 2 * DAY + 60, det.labels) == []


def test_one_device_counts_once_towards_a_shared_apex(make_detector):
    det = settled(make_detector)
    rotate(det)
    det.process_query(q("usual.example", t=LATER + 200, ip=NEW_IP))
    assert det.state.apex_prevalence("usual.example") == 1


def test_what_was_learned_before_the_rotation_was_recognised_is_kept(make_detector):
    det = settled(make_detector)
    asleep = LATER + 100
    det.probe = lambda ips, wait, **_: {}
    det.process_devices([Device(hwaddr=NEW, ips=(NEW_IP,), first_seen=T0 + asleep)], T0 + asleep)
    det.process_query(q("early.example", t=asleep + 1, ip=NEW_IP))
    det.process_query(q("usual.example", t=asleep + 2, ip=NEW_IP))
    det.rotations.answered(NEW, "Aswins-iPad", "mDNS", T0 + asleep + DAY, {})
    assert det.state.client_first_seen(NEW) is None
    assert det.state.client_first_seen(OLD) == T0
    assert det.state.domain_first_seen(OLD, "early.example") == T0 + asleep + 1
    assert det.state.domain_first_seen(OLD, "usual.example") == T0  # the older sighting wins
    assert det.state.apex_prevalence("usual.example") == 1


def test_every_mac_of_a_device_stays_one_device(make_detector):
    det = settled(make_detector)
    rotate(det)
    rotate(det, mac=THIRD, ip=THIRD_IP, t=LATER + 200)
    det.rotations.answered(OLD, "Aswins-iPad", "mDNS", T0 + LATER + 300, {})  # back on a MAC it used before
    assert det.state.device_of(NEW) == det.state.device_of(THIRD) == det.state.device_of(OLD) == OLD


def test_a_name_from_an_untrusted_probe_links_nothing(make_detector):
    det = settled(make_detector)
    rotate(det, source="NetBIOS")
    assert det.state.device_of(NEW) == NEW


def test_a_burned_in_mac_is_never_linked_to_a_device(make_detector):
    det = settled(make_detector)
    rotate(det, mac="00:11:22:33:44:55")
    assert det.state.device_of("00:11:22:33:44:55") == "00:11:22:33:44:55"
