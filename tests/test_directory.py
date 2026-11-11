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
    record = {"label": "old", "mac": MAC, "ips": [IP]}
    assert directory(tmp_path, {MAC: "New"}).relabel([record])[0]["label"] == "New"


def test_a_query_is_labelled_in_the_same_order_as_a_device(tmp_path):
    d = directory(tmp_path, saved={MAC: ("Tab", "SSDP")})
    assert d.query_label(MAC, IP, "host") == "Tab"
    d = directory(tmp_path)
    d.learn([Device(hwaddr=MAC, ips=(IP,), first_seen=T0, vendor="LG")])
    assert d.query_label(MAC, IP, "host") == "host"
    assert d.query_label(MAC, IP, None) == "LG device"
    assert d.query_label(MAC, IP, IP) == "LG device"     # Pi-hole shows the IP when it has no hostname
    assert d.query_label(None, IP, None) == IP


# --- find: one Found per Device (ADR 0003), never by label --------------------------------------

def test_find_never_makes_two_devices_one_because_their_labels_match(tmp_path):
    a = Device(hwaddr=MAC, ips=(IP,), first_seen=T0, vendor="Apple", last_query=T0)
    b = Device(hwaddr=OLD, ips=("192.0.2.41",), first_seen=T0, vendor="Apple", last_query=T0 - 5)
    found = directory(tmp_path).find("apple", [a, b])
    assert [f.macs for f in found] == [(a,), (b,)]


def test_find_makes_a_devices_linked_macs_one_whatever_they_are_called(tmp_path):
    new = Device(hwaddr=MAC, ips=(IP,), first_seen=T0, vendor="Apple", last_query=T0)
    old = Device(hwaddr=OLD, ips=("192.0.2.41",), first_seen=T0 - 9, last_query=T0 - 60)
    other = Device(hwaddr="02:00:00:00:00:42", ips=("192.0.2.42",), first_seen=T0, last_query=T0)
    store = NameStore(tmp_path / "names.json")
    d = Directory(lambda: {OLD: "Kitchen iPad"}, store, device_of=lambda m: OLD if m == MAC else m)
    (found,) = d.find("kitchen", [new, old, other])   # only the old MAC carries the name
    assert found.device == OLD and found.macs == (new, old) and found.current == new
    assert found.label == "Kitchen iPad"               # a chosen name beats the new MAC's vendor guess
