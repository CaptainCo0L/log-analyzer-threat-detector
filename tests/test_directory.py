from pihole_detector.directory import Directory
from pihole_detector.model import Device
from pihole_detector.namestore import NameStore
from conftest import T0

IP, MAC = "192.0.2.40", "02:00:00:00:00:40"
OLD = "02:00:00:00:00:41"


def directory(tmp_path, comments=None, saved=None):
    store = NameStore(tmp_path / "names.json")
    store.update(saved or {}, T0)
    return Directory(lambda: comments or {}, store)


def dev(**kw):
    return Device(**{"hwaddr": MAC, "ips": ("fe80::1", IP), "first_seen": T0, **kw})


def test_label_order_is_comment_saved_name_hostname_vendor_mac(tmp_path):
    saved = {MAC: ("Galaxy Tab", "mDNS")}
    assert directory(tmp_path, {MAC: "Kitchen"}, saved).label(dev(name="host")) == "Kitchen"
    assert directory(tmp_path, {IP: "By IP"}, saved).label(dev()) == "By IP"
    assert directory(tmp_path, saved=saved).label(dev(name="host")) == "Galaxy Tab"
    assert directory(tmp_path).label(dev(name="host", vendor="Apple")) == "host"
    assert directory(tmp_path).label(dev(vendor="Apple")) == "Apple device"
    assert directory(tmp_path).label(dev()) == MAC


def test_source_says_where_the_label_came_from(tmp_path):
    assert directory(tmp_path, {IP: "By IP"}).source(dev()) == "Clients comment"
    assert directory(tmp_path, saved={MAC: ("Tab", "SSDP")}).source(dev()) == "discovered (SSDP)"
    assert directory(tmp_path).source(dev(name="host")) == "Pi-hole hostname"
    assert directory(tmp_path).source(dev()) == "vendor guess"


def test_previous_mac_trusts_only_the_names_rotation_sync_trusts(tmp_path):
    d = directory(tmp_path, saved={OLD: ("Aswins-iPad", "mDNS")})
    assert d.previous_mac(MAC, "aswins-ipad", "Bonjour") == OLD
    assert d.previous_mac(MAC, "Aswins-iPad", "NetBIOS") is None   # anything can claim a NetBIOS name
    d = directory(tmp_path, saved={OLD: ("Aswins-iPad", "SSDP")})
    assert d.previous_mac(MAC, "Aswins-iPad", "mDNS") is None      # nor is the saved one trusted


def test_relabel_names_records_by_their_mac(tmp_path):
    record = {"client": "old", "address": f"{IP} · {MAC}"}
    assert directory(tmp_path, {MAC: "New"}).relabel([record])[0]["client"] == "New"
