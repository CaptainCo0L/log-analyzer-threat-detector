"""Planning a change to Pi-hole Clients: the ops to run and the ops that reverse them."""

from pihole_detector.changes import Change, rename, set_group
from pihole_detector.model import Client

A, B = "02:00:00:00:00:0a", "02:00:00:00:00:0b"
ENTRY = Client(mac=A, client=A.upper(), comment="Old", groups=(0, 1))


def test_rename_updates_an_entry_and_creates_one_in_default_for_a_mac_without():
    assert rename([A, B], [ENTRY], "New") == Change(
        ops=[["update_client", A.upper(), "New", [0, 1]], ["add_client", B, "New", [0]]],
        undo=[["update_client", A.upper(), "Old", [0, 1]], ["delete_client", B]])


def test_adding_to_a_group_keeps_the_entrys_groups():
    assert set_group({A: "PC"}, [ENTRY], 2, remove=False) == Change(
        ops=[["update_client", A.upper(), "Old", [0, 1, 2]]],
        undo=[["update_client", A.upper(), "Old", [0, 1]]])


def test_adding_to_a_group_restores_default_on_an_entry_that_lost_it():
    entry = Client(mac=A, client=A, comment="Old", groups=(1,))
    assert set_group({A: "PC"}, [entry], 2, remove=False).ops == [["update_client", A, "Old", [0, 1, 2]]]


def test_adding_a_mac_without_an_entry_creates_one_named_after_the_device():
    assert set_group({B: "LG device"}, [ENTRY], 2, remove=False) == Change(
        ops=[["add_client", B, "LG device", [0, 2]]], undo=[["delete_client", B]])


def test_removing_from_a_group_drops_only_that_group():
    assert set_group({A: "PC"}, [ENTRY], 1, remove=True) == Change(
        ops=[["update_client", A.upper(), "Old", [0]]],
        undo=[["update_client", A.upper(), "Old", [0, 1]]])


def test_removing_a_mac_without_an_entry_changes_nothing():
    assert set_group({B: "LG device"}, [ENTRY], 1, remove=True) == Change(ops=[], undo=[])
