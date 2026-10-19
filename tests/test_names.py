import sqlite3

from pihole_detector.__main__ import cmd_names
from pihole_detector.config import Config
from pihole_detector.intel import read_client_comments
from pihole_detector.model import Device
from pihole_detector.names import build_names_report
from conftest import T0


def dev(mac, ip, vendor=None):
    return Device(hwaddr=mac, ips=(ip,), first_seen=T0, vendor=vendor)


def rows(out):
    """The device table as {ip: [cells]}."""
    table = out.split("## Devices\n", 1)[1].split("\n\n", 1)[0].splitlines()
    cells = [[c.strip() for c in line.strip("|").split("|")] for line in table[2:]]
    return {c[0]: c[1:] for c in cells}


A, B, C = "02:00:00:00:00:0a", "02:00:00:00:00:0b", "02:00:00:00:00:0c"


def test_existing_clients_comment_wins_and_is_never_overridden():
    out = build_names_report([dev(A, "192.0.2.10")], {A: "AswinPC"}, {"192.0.2.10": {"mDNS": "desktop-x"}})
    mac, name, source, evidence, notes = rows(out)["192.0.2.10"]
    assert (name, source) == ("AswinPC", "Clients comment")
    assert evidence == "mDNS: desktop-x"  # still shown, so a stale comment is visible


def test_comment_can_be_keyed_by_ip_instead_of_mac():
    out = build_names_report([dev(A, "192.0.2.10")], {"192.0.2.10": "Printer"}, {})
    assert rows(out)["192.0.2.10"][1:3] == ["Printer", "Clients comment"]


def test_mdns_beats_ssdp_beats_netbios():
    found = {"192.0.2.10": {"NetBIOS": "NB", "SSDP": "UPNP", "mDNS": "MD"},
             "192.0.2.11": {"NetBIOS": "NB", "SSDP": "UPNP"},
             "192.0.2.12": {"NetBIOS": "NB"}}
    out = build_names_report([dev(A, "192.0.2.10"), dev(B, "192.0.2.11"), dev(C, "192.0.2.12")], {}, found)
    table = rows(out)
    assert table["192.0.2.10"][1:3] == ["MD", "mDNS"]
    assert table["192.0.2.11"][1:3] == ["UPNP", "SSDP"]
    assert table["192.0.2.12"][1:3] == ["NB", "NetBIOS"]
    assert table["192.0.2.10"][3] == "mDNS: MD · SSDP: UPNP · NetBIOS: NB"


def test_vendor_is_a_last_resort_guess_and_unknown_is_a_question_mark():
    out = build_names_report([dev(A, "192.0.2.10", vendor="Sony Corporation"), dev(B, "192.0.2.11")], {}, {})
    table = rows(out)
    assert table["192.0.2.10"][1:3] == ["Sony Corporation device", "vendor guess"]
    assert table["192.0.2.11"][1:3] == ["?", "-"]


def test_devices_with_no_answer_are_told_to_try_again_unless_already_named():
    out = build_names_report([dev(A, "192.0.2.10"), dev(B, "192.0.2.11")], {B: "TV"}, {})
    table = rows(out)
    assert "no answer" in table["192.0.2.10"][4]
    assert "no answer" not in table["192.0.2.11"][4]


def test_two_macs_advertising_the_same_name_are_flagged():
    found = {"192.0.2.10": {"mDNS": "Aswins-iPad"}, "192.0.2.11": {"mDNS": "aswins-ipad"}}
    table = rows(build_names_report([dev(A, "192.0.2.10"), dev(B, "192.0.2.11")], {}, found))
    assert f"same name as {B}" in table["192.0.2.10"][4]
    assert f"same name as {A}" in table["192.0.2.11"][4]


def test_copy_block_lists_only_new_probe_names():
    found = {"192.0.2.10": {"mDNS": "ipad"}, "192.0.2.11": {"mDNS": "tv"}}
    devices = [dev(A, "192.0.2.10"), dev(B, "192.0.2.11"), dev(C, "192.0.2.12", vendor="Acme")]
    out = build_names_report(devices, {B: "Already named"}, found)
    block = out.split("## Add to Pi-hole Clients\n", 1)[1]
    assert f"{A}  ipad" in block
    assert B not in block and C not in block  # named already / only a vendor guess


def test_placeholder_devices_without_a_real_mac_are_skipped_and_rows_sort_by_ip():
    devices = [dev(A, "192.0.2.10"), dev(B, "192.0.2.9"), Device(hwaddr="ip-127.0.0.1", ips=("127.0.0.1",), first_seen=T0)]
    assert list(rows(build_names_report(devices, {}, {}))) == ["192.0.2.9", "192.0.2.10"]


# --- reading Pi-hole's comments, and the command that ties it together ---------------------------

def gravity_with_clients(path, clients):
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE client (id INTEGER PRIMARY KEY, ip TEXT, comment TEXT)")
    db.executemany("INSERT INTO client (ip, comment) VALUES (?, ?)", clients)
    db.commit()
    db.close()


def test_read_client_comments_lowercases_keys_and_skips_blank_comments(tmp_path):
    path = tmp_path / "gravity.db"
    gravity_with_clients(path, [("78:0B:4A:97:5E:A8", " AswinPC "), ("192.0.2.5", ""), ("192.0.2.6", None)])
    assert read_client_comments(path) == {"78:0b:4a:97:5e:a8": "AswinPC"}
    assert read_client_comments(tmp_path / "missing.db") == {}


class FakeApi:
    def __init__(self, devices):
        self._devices = devices
        self.logged_out = False

    def devices(self):
        return self._devices

    def logout(self):
        self.logged_out = True


def test_cmd_names_probes_only_ipv4_of_real_devices_and_logs_out(tmp_path, capsys):
    gravity = tmp_path / "gravity.db"
    gravity_with_clients(gravity, [(A, "AswinPC")])
    api = FakeApi([
        Device(hwaddr=A, ips=("fe80::1", "192.0.2.10"), first_seen=T0),
        Device(hwaddr=B, ips=("192.0.2.11",), first_seen=T0),
        Device(hwaddr="ip-127.0.0.1", ips=("127.0.0.1",), first_seen=T0),
    ])
    probed = {}

    def fake_probe(ips, wait):
        probed.update(ips=list(ips), wait=wait)
        return {"192.0.2.11": {"mDNS": "tv"}}

    assert cmd_names(Config(gravity_db=str(gravity)), 3, api=api, probe=fake_probe) == 0
    out = capsys.readouterr().out
    assert probed == {"ips": ["192.0.2.10", "192.0.2.11"], "wait": 3}
    assert "AswinPC" in out and f"{B}  tv" in out
    assert api.logged_out
