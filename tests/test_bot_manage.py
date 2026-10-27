"""Stage 3: managing Pi-hole from chat. Every change replies with an Undo and is logged."""

import json

from pihole_detector.bot import Bot
from pihole_detector.model import Device
from pihole_detector.rotation import Client
from conftest import IOT_IP, IOT_MAC, PC_IP, PC_MAC, T0

OWNER = 42
TRACKER = r"(\.|^)tracker\.example$"


class FakePihole:
    def __init__(self):
        self.calls = []
        self.entries = [Client(mac=PC_MAC, client=PC_MAC.upper(), comment="AswinPC", groups=(0, 1))]
        self.devices_ = [Device(hwaddr=PC_MAC, ips=(PC_IP,), first_seen=T0, last_query=T0, vendor="Acme"),
                         Device(hwaddr=IOT_MAC, ips=(IOT_IP,), first_seen=T0, last_query=T0, vendor="LG")]
        self.missing = set()  # domains whose delete gets a 404

    def devices(self):
        return list(self.devices_)

    def clients(self):
        return list(self.entries)

    def groups(self):
        return {0: "Default", 1: "Aswin", 2: "IoT"}

    def add_domain(self, list_type, kind, domain, comment=""):
        self.calls.append(("add_domain", list_type, kind, domain))

    def delete_domain(self, list_type, kind, domain):
        if domain in self.missing:
            from pihole_detector.source import ApiError
            raise ApiError(f"DELETE /domains/{list_type}/{kind}: HTTP 404")
        self.calls.append(("delete_domain", list_type, kind, domain))

    def set_blocking(self, enabled, timer=None):
        self.calls.append(("blocking", enabled, timer))

    def add_client(self, entry):
        self.calls.append(("add_client", entry.client, entry.comment, entry.groups))
        self.entries.append(entry)

    def update_client(self, entry):
        self.calls.append(("update_client", entry.client, entry.comment, entry.groups))
        self.entries = [entry if c.client == entry.client else c for c in self.entries]

    def delete_client(self, client):
        self.calls.append(("delete_client", client))
        self.entries = [c for c in self.entries if c.client != client]


def message(text, date=T0, update_id=1):
    return {"update_id": update_id, "message": {"message_id": 100, "date": int(date), "text": text,
                                                "chat": {"id": OWNER, "type": "private"}, "from": {"id": OWNER}}}


def press(data, update_id=2):
    return {"update_id": update_id, "callback_query": {
        "id": "cb1", "from": {"id": OWNER}, "data": data,
        "message": {"message_id": 55, "date": int(T0), "chat": {"id": OWNER, "type": "private"}}}}


def setup(make_detector, tmp_path):
    det = make_detector(telegram_chat_id=str(OWNER), bot_enabled=True,
                        pihole_changes_path=str(tmp_path / "pihole_changes.jsonl"))
    det.intel.names[PC_MAC] = "AswinPC"
    api = FakePihole()
    return Bot(det, api, det.telegram, started=T0), det, api


def last_button(det, label):
    payload = det.telegram.payloads()[-1]
    return next(b for row in payload["reply_markup"]["inline_keyboard"] for b in row if label in b["text"])


def undo_last(bot, det, update_id=9):
    bot.handle(press(last_button(det, "Undo")["callback_data"], update_id=update_id), T0 + 5)


# --- block / allow -------------------------------------------------------------------------

def test_block_denies_the_apex_and_subdomains_and_undo_removes_it(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/block ads.tracker.example"), T0)
    assert api.calls == [("add_domain", "deny", "regex", TRACKER)]
    assert "tracker.example" in det.telegram.messages[-1] and "subdomains" in det.telegram.messages[-1]
    undo_last(bot, det)
    assert api.calls[-1] == ("delete_domain", "deny", "regex", TRACKER)


def test_block_exact_and_allow_variants(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/block exact ads.tracker.example"), T0)
    bot.handle(message("/allow cdn.shop.example"), T0)
    bot.handle(message("/allow wild img.cdn.example"), T0)
    assert api.calls == [("add_domain", "deny", "exact", "ads.tracker.example"),
                         ("add_domain", "allow", "exact", "cdn.shop.example"),
                         ("add_domain", "allow", "regex", r"(\.|^)cdn\.example$")]


def test_anything_but_a_plain_domain_is_refused(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    for text in ("/block", "/block *.tracker.example", "/block tracker", "/allow a;b.example", "/block exact"):
        bot.handle(message(text), T0)
    assert api.calls == [] and all("Usage" in m or "plain domain" in m for m in det.telegram.messages)


def test_unblock_removes_what_the_bot_could_have_added_and_says_what_it_found(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    api.missing = {"ads.tracker.example"}
    bot.handle(message("/unblock ads.tracker.example"), T0)
    assert api.calls == [("delete_domain", "deny", "regex", TRACKER)]
    assert "Unblocked" in det.telegram.messages[-1]
    api.missing = {TRACKER, "ads.tracker.example"}
    bot.handle(message("/unblock ads.tracker.example"), T0)
    assert "wasn't on" in det.telegram.messages[-1]


def test_unallow_mirrors_unblock(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/unallow cdn.shop.example"), T0)
    assert ("delete_domain", "allow", "exact", "cdn.shop.example") in api.calls


# --- pause / resume ------------------------------------------------------------------------

def test_pause_uses_piholes_timer_defaults_to_five_minutes_and_caps_at_an_hour(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/pause"), T0)
    bot.handle(message("/pause 90"), T0)
    bot.handle(message("/pause soon"), T0)
    assert api.calls == [("blocking", False, 300), ("blocking", False, 3600), ("blocking", False, 300)]
    assert "60 min" in det.telegram.messages[1]
    bot.handle(press(last_button(det, "Resume")["callback_data"]), T0 + 5)
    assert api.calls[-1] == ("blocking", True, None)
    bot.handle(message("/resume"), T0)
    assert api.calls[-1] == ("blocking", True, None)


# --- stale commands ------------------------------------------------------------------------

def test_a_write_command_from_more_than_five_minutes_ago_is_not_run(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/block tracker.example", date=T0 - 600), T0)
    bot.handle(message("/pause", date=T0 - 600), T0)
    assert api.calls == [] and all("Send it again" in m for m in det.telegram.messages)
    bot.handle(message("/status", date=T0 - 600), T0)  # read commands still run
    assert "Status" in det.telegram.messages[-1]


# --- name / group --------------------------------------------------------------------------

def test_name_renames_an_existing_entry_and_undo_restores_the_old_name(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/name aswinpc Aswin desktop"), T0)
    assert api.calls == [("update_client", PC_MAC.upper(), "Aswin desktop", (0, 1))]
    undo_last(bot, det)
    assert api.calls[-1] == ("update_client", PC_MAC.upper(), "AswinPC", (0, 1))


def test_name_creates_an_entry_in_default_for_a_device_without_one(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message(f"/name {IOT_IP} LG Fridge"), T0)
    assert api.calls == [("add_client", IOT_MAC, "LG Fridge", (0,))]
    undo_last(bot, det)
    assert api.calls[-1] == ("delete_client", IOT_MAC)


def test_name_needs_a_device_and_a_name(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/name aswinpc"), T0)
    bot.handle(message("/name toaster Kitchen"), T0)
    assert api.calls == [] and "Usage" in det.telegram.messages[0] and "No device" in det.telegram.messages[1]


def test_group_adds_a_device_to_a_group_keeping_default(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message(f"/group {IOT_MAC} iot"), T0)
    assert api.calls == [("add_client", IOT_MAC, "LG device", (0, 2))]
    bot.handle(message("/group aswinpc IoT"), T0)
    assert api.calls[-1] == ("update_client", PC_MAC.upper(), "AswinPC", (0, 1, 2))
    undo_last(bot, det)
    assert api.calls[-1] == ("update_client", PC_MAC.upper(), "AswinPC", (0, 1))


def test_group_remove_asks_first_and_never_removes_default(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/group aswinpc default remove"), T0)
    refusal = det.telegram.payloads()[-1]
    assert api.calls == [] and "always stay in Default" in refusal["text"]
    assert "reply_markup" not in refusal  # refused outright: no confirm button to press
    bot.handle(message("/group aswinpc aswin remove"), T0)
    assert api.calls == []  # nothing until confirmed
    bot.handle(press(last_button(det, "Remove")["callback_data"]), T0 + 5)
    assert api.calls == [("update_client", PC_MAC.upper(), "AswinPC", (0,))]


def test_an_unknown_group_lists_the_real_ones(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/group aswinpc kids"), T0)
    assert api.calls == [] and "Aswin" in det.telegram.messages[-1] and "IoT" in det.telegram.messages[-1]


# --- the change log ------------------------------------------------------------------------

def test_every_change_and_undo_is_logged(make_detector, tmp_path):
    bot, det, api = setup(make_detector, tmp_path)
    bot.handle(message("/block tracker.example"), T0)
    undo_last(bot, det)
    lines = [json.loads(line) for line in (tmp_path / "pihole_changes.jsonl").read_text().splitlines()]
    assert [line["command"] for line in lines] == ["/block tracker.example", "undo"]
    assert lines[0]["ops"] == [["add_domain", "deny", "regex", TRACKER]]


def test_new_commands_are_in_the_menu():
    from pihole_detector.bot import BOT_COMMANDS
    assert {"block", "allow", "unblock", "unallow", "pause", "resume", "name", "group"} <= {c for c, _ in BOT_COMMANDS}
