"""plan_sync: which Pi-hole Clients entries follow a device onto its new private MAC."""

from pihole_detector.rotation import Client, plan_sync

NEW = "06:da:8f:c5:97:97"
OLD1 = "ea:65:e1:2f:e9:83"
OLD2 = "da:b3:28:6c:be:64"
PC = "78:0b:4a:97:5e:a8"  # burned-in (globally administered)


def names(*entries):
    return {mac: {"name": name, "source": source} for mac, name, source in entries}


def client(mac, comment="iPad", groups=(0, 1)):
    return Client(mac=mac, client=mac.upper(), comment=comment, groups=tuple(groups))


IPAD = names((NEW, "Aswins-iPad", "mDNS"), (OLD1, "Aswins-iPad", "mDNS"), (OLD2, "aswins-ipad", "Bonjour"))


def test_new_mac_gets_the_newest_entrys_comment_and_groups():
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1, "iPad (current)", (0, 1)), client(OLD2, "old iPad", (0, 1))],
                     IPAD, {OLD1: 200, OLD2: 100})
    assert plan.add == Client(mac=NEW, client=NEW, comment="iPad (current)", groups=(0, 1))
    assert plan.reason is None


def test_default_group_is_always_kept():
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1, groups=(1,))], IPAD, {OLD1: 1})
    assert plan.add.groups == (0, 1)


def test_only_the_two_most_recently_seen_macs_stay():
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1), client(OLD2)], IPAD, {OLD1: 200, OLD2: 100})
    assert [c.mac for c in plan.delete] == [OLD2]
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1), client(OLD2)], IPAD, {OLD1: 100, OLD2: 200})
    assert [c.mac for c in plan.delete] == [OLD1]


def test_keep_is_configurable():
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1), client(OLD2)], IPAD, {OLD1: 2, OLD2: 1}, keep=3)
    assert plan.delete == []


def test_a_burned_in_mac_is_never_deleted():
    saved = names((NEW, "AswinPC", "mDNS"), (PC, "AswinPC", "mDNS"), (OLD1, "AswinPC", "mDNS"))
    plan = plan_sync(NEW, "AswinPC", "mDNS", [client(PC), client(OLD1)], saved, {PC: 1, OLD1: 2})
    assert plan.add is not None and plan.delete == []


def test_names_from_other_probes_are_not_trusted():
    for source in ("SSDP", "NetBIOS", "nmap"):
        plan = plan_sync(NEW, "Aswins-iPad", source, [client(OLD1)], IPAD, {OLD1: 1})
        assert plan.add is None and plan.delete == [] and "mDNS" in plan.reason


def test_entries_saved_under_an_untrusted_source_are_not_the_device():
    saved = names((NEW, "Aswins-iPad", "mDNS"), (OLD1, "Aswins-iPad", "nmap"))
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1)], saved, {OLD1: 1})
    assert plan.add is None and "no Pi-hole Clients entry" in plan.reason


def test_nothing_happens_without_an_entry_to_copy():
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(PC, "AswinPC")], IPAD, {})
    assert plan.add is None and plan.delete == [] and "no Pi-hole Clients entry" in plan.reason


def test_entries_that_disagree_on_groups_are_left_alone():
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1, groups=(0, 1)), client(OLD2, groups=(0, 2))],
                     IPAD, {OLD1: 2, OLD2: 1})
    assert plan.add is None and plan.delete == [] and "groups differ" in plan.reason


def test_an_entry_with_no_saved_name_is_never_touched():
    stranger = "f2:72:dd:93:4e:32"
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(OLD1), client(OLD2), client(stranger)],
                     IPAD, {OLD1: 3, OLD2: 2, stranger: 1})
    assert stranger not in [c.mac for c in plan.delete]


def test_a_mac_that_is_already_a_client_or_burned_in_is_not_synced():
    plan = plan_sync(NEW, "Aswins-iPad", "mDNS", [client(NEW), client(OLD1)], IPAD, {OLD1: 1})
    assert plan.add is None and plan.delete == [] and "already" in plan.reason
    plan = plan_sync(PC, "Aswins-iPad", "mDNS", [client(OLD1)], {**IPAD, PC: {"name": "Aswins-iPad", "source": "mDNS"}}, {})
    assert plan.add is None and "private" in plan.reason
