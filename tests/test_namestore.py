import json
import os

from pihole_detector.names import best_probe
from pihole_detector.namestore import NameStore
from conftest import T0

A, B = "02:00:00:00:00:0a", "02:00:00:00:00:0b"


def test_missing_file_is_an_empty_store(tmp_path):
    assert NameStore(tmp_path / "names.json").name(A) is None


def test_saved_names_survive_a_reload_from_disk(tmp_path):
    path = tmp_path / "names.json"
    store = NameStore(path)
    store.update({A: ("Aswins-iPad", "mDNS")}, T0)
    store.save()
    reopened = NameStore(path)
    assert reopened.name(A) == "Aswins-iPad"
    assert reopened.entries[A] == {"name": "Aswins-iPad", "source": "mDNS", "confirmed": T0}


def test_a_rename_is_reported_and_silent_devices_are_kept(tmp_path):
    store = NameStore(tmp_path / "names.json")
    store.update({A: ("old-name", "mDNS"), B: ("tv", "SSDP")}, T0)
    changes = store.update({A: ("new-name", "mDNS")}, T0 + 100)
    assert changes == [(A, "old-name", "new-name")]
    assert store.name(B) == "tv"
    assert store.entries[B]["confirmed"] == T0  # not seen this run, so not re-confirmed


def test_an_unchanged_name_only_refreshes_the_confirmed_time(tmp_path):
    store = NameStore(tmp_path / "names.json")
    store.update({A: ("tv", "SSDP")}, T0)
    assert store.update({A: ("tv", "SSDP")}, T0 + 100) == []
    assert store.entries[A]["confirmed"] == T0 + 100


def test_new_names_are_reported_as_changes_from_nothing(tmp_path):
    assert NameStore(tmp_path / "n.json").update({A: ("tv", "SSDP")}, T0) == [(A, None, "tv")]


def test_reload_picks_up_a_file_written_by_another_process(tmp_path):
    path = tmp_path / "names.json"
    service = NameStore(path)
    assert service.name(A) is None
    other = NameStore(path)
    other.update({A: ("tv", "SSDP")}, T0)
    other.save()
    os.utime(path, (T0 + 50, T0 + 50))
    assert service.reload_if_changed() is True
    assert service.name(A) == "tv"
    assert service.reload_if_changed() is False


def test_a_corrupt_file_is_ignored_rather_than_fatal(tmp_path):
    path = tmp_path / "names.json"
    path.write_text("{not json", encoding="utf-8")
    store = NameStore(path)
    assert store.name(A) is None
    store.update({A: ("tv", "SSDP")}, T0)
    store.save()
    assert json.loads(path.read_text(encoding="utf-8"))[A]["name"] == "tv"


def test_best_probe_follows_the_source_order_and_skips_nothing_found():
    assert best_probe({"NetBIOS": "NB", "SSDP": "UPNP"}) == ("UPNP", "SSDP")
    assert best_probe({"Bonjour": "Aswin's iPad", "mDNS": "ipad"}) == ("ipad", "mDNS")
    assert best_probe({}) is None


# --- relabelling records for display ------------------------------------------------------------

from pihole_detector.namestore import relabel


def test_relabel_replaces_the_stored_name_without_touching_the_original_records():
    records = [{"label": "(192.0.2.10, 02:00:00:00:00:0a)", "mac": A, "ips": ["192.0.2.10"], "rule": "x"}]
    out = relabel(records, {A: "Aswins-iPad"}.get)
    assert out[0]["label"] == "Aswins-iPad" and out[0]["rule"] == "x"
    assert records[0]["label"] == "(192.0.2.10, 02:00:00:00:00:0a)"


def test_relabel_keeps_the_stored_name_when_there_is_no_mac_or_no_better_name():
    records = [{"label": "192.0.2.10", "mac": ""}, {"label": "old", "mac": B}]
    assert [r["label"] for r in relabel(records, {A: "x"}.get)] == ["192.0.2.10", "old"]


def test_nmap_is_the_least_trusted_probe():
    assert best_probe({"nmap": "tplinkdeco.net", "NetBIOS": "NB"}) == ("NB", "NetBIOS")
    assert best_probe({"nmap": "tplinkdeco.net"}) == ("tplinkdeco.net", "nmap")
