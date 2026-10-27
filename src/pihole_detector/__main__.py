"""CLI: `python -m pihole_detector run | replay FILE | seed | digest | report | names | clients-undo`."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from . import clientlog
from .bot import alert_buttons, drain, start_bot
from .config import Config
from .rules import block_hint
from .detector import Detector
from .discovery import discover, nmap_options
from .intel import GravityIntel, read_client_comments
from .model import Alert
from .namestore import NameStore, best_probe, relabel
from .names import build_names_report, ipv4_of
from .report import build_report, load_records
from .sinks import JsonlSink, Telegram, build_digest, format_down, format_push, format_test, format_up
from .source import ApiError, PiholeApi, Tail, read_replay
from .state import State

log = logging.getLogger("pihole_detector")
HEARTBEAT = Path("/tmp/heartbeat")
MAX_CATCHUP = 6 * 3600


def build(cfg: Config, state_path: str | None = None, alerts_path: str | None = None):
    state = State(state_path or cfg.state_db)
    extra = []
    if cfg.threat_file:
        with open(cfg.threat_file, encoding="utf-8") as handle:
            extra = [line.strip() for line in handle if line.strip() and not line.startswith("#")]
    intel = GravityIntel(Path(cfg.gravity_db), cfg.threat_list_match, cfg.iot_group,
                         extra_threats=extra, extra_iot=cfg.extra_iot_clients)
    intel.refresh()
    telegram = Telegram(cfg.telegram_token, cfg.telegram_chat_id, cfg.push_cap_per_hour)
    return Detector(cfg, state, intel, JsonlSink(alerts_path or cfg.alerts_path), telegram)


def cmd_replay(cfg: Config, path: str, alerts_out: str) -> int:
    """Run a recorded/synthetic JSONL through the full pipeline with an in-memory state."""
    det = build(cfg, ":memory:", alerts_out)
    det.digests = False
    total = 0
    for kind, payload, when in read_replay(path):
        if kind == "devices":
            total += len(det.process_devices(payload, when))
        else:
            total += len(det.process_query(payload))
            total += len(det.tick(when))
    det.state.close()
    for record in det.jsonl.since(0):
        print(f"[{record['severity']}] {record['rule']}: {record['message']}")
    print(f"{total} alert(s) -> {alerts_out}", file=sys.stderr)
    return 0


def cmd_seed(cfg: Config, days: float) -> int:
    """Backfill client baselines from FTL's on-disk history. Emits no alerts."""
    det = build(cfg)
    api = PiholeApi(cfg.pihole_url, cfg.pihole_password)
    try:
        now = time.time()
        det.process_devices(api.devices(), now)
        start = now - days * 86400
        count = 0
        # One day per request keeps each response bounded.
        for day_start in range(int(start), int(now), 86400):
            for q in api.queries_since(day_start, min(day_start + 86400, now), disk=True, page=5000):
                det.learn(q)
                count += 1
            det.state.commit()
            log.info("seeded through %s (%d queries)", time.strftime("%Y-%m-%d", time.localtime(day_start)), count)
        det.state.put("last_time", now)
        det.state.put("seeded_at", now)
        det.state.commit()
        print(f"seeded {count} queries over {days:g} days")
        return 0
    finally:
        api.logout()
        det.state.close()


def cmd_run(cfg: Config) -> int:
    det = build(cfg)
    api = PiholeApi(cfg.pihole_url, cfg.pihole_password)
    det.clients_api = api  # used only when ROTATION_SYNC is on
    bot = start_bot(det, api)
    stopping = False

    def stop(*_):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    now = time.time()
    tail = Tail(max(det.state.get("last_time", now - 60), now - MAX_CATCHUP))
    failures, down_since = 0, None
    next_devices = next_intel = 0.0
    log.info("running: push=%s poll=%.1fs threat domains=%d", cfg.push_enabled, cfg.poll_seconds, len(det.intel.threats))

    while not stopping:
        now = time.time()
        HEARTBEAT.touch()
        try:
            if now >= next_intel:
                det.intel.refresh()
                next_intel = now + cfg.intel_seconds
            if now >= next_devices:
                det.process_devices(api.devices(), now)
                next_devices = now + cfg.devices_seconds
            for q in tail.feed(api.queries_since(tail.since), now):
                det.process_query(q)
            det.state.put("last_time", tail.mark)
            if failures >= cfg.fail_threshold and cfg.health_push_enabled:
                det.telegram.send(format_up(now - down_since), now, capped=False)
            failures, down_since = 0, None
        except ApiError as exc:
            failures += 1
            det.stats["api_failures"] += 1
            down_since = down_since or now
            log.warning("poll failed (%d in a row): %s", failures, exc)
            if failures == cfg.fail_threshold and cfg.health_push_enabled:
                det.telegram.send(format_down(failures, str(exc)), now, capped=False)
        if bot:
            drain(bot[1], bot[0], det.state, now)
        det.tick(now)
        det.state.commit()
        # Back off while failing (3, 6, 12, 24, 30 s...) instead of retrying a login every poll.
        time.sleep(min(cfg.poll_seconds * 2 ** min(failures, 4), 30) if failures else cfg.poll_seconds)

    log.info("stopping")
    api.logout()
    det.state.close()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="pihole_detector", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("run", help="poll the Pi-hole API and alert in real time")
    rp = sub.add_parser("replay", help="run a JSONL fixture through the pipeline")
    rp.add_argument("file")
    rp.add_argument("--alerts-out", default="reports/replay-alerts.jsonl")
    sp = sub.add_parser("seed", help="backfill baselines from FTL history")
    sp.add_argument("--days", type=float, default=7)
    sub.add_parser("digest", help="send the digest now (tests the Telegram setup)")
    sub.add_parser("test-push", help="send one test Telegram message")
    sub.add_parser("preview", help="send an example alert and daily report")
    rep = sub.add_parser("report", help="print a Markdown review of alerts.jsonl")
    rep.add_argument("--days", type=float, default=7)
    rep.add_argument("--file", help="alerts file (default: ALERTS_PATH)")
    nm = sub.add_parser("names", help="suggest names for Pi-hole's devices (mDNS/SSDP/NetBIOS/nmap); writes nothing")
    nm.add_argument("--wait", type=float, default=8, help="seconds to listen for replies")
    nm.add_argument("--save", action="store_true", help="store the names found, for alerts and reports to use")
    sub.add_parser("clients-undo", help="reverse the last rotation sync change to Pi-hole Clients")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    if args.cmd == "replay":
        out = Path(args.alerts_out)
        out.unlink(missing_ok=True)
        return cmd_replay(cfg, args.file, str(out))
    if args.cmd == "seed":
        return cmd_seed(cfg, args.days)
    if args.cmd == "digest":
        det = build(cfg)
        det.maybe_digest(time.time(), force=True)
        det.state.close()
        return 0
    if args.cmd == "test-push":
        ok = Telegram(cfg.telegram_token, cfg.telegram_chat_id, 1).send(
            format_test(cfg.push_enabled), time.time(), capped=False)
        print("sent" if ok else "FAILED (see log)")
        return 0 if ok else 1
    if args.cmd == "preview":
        return cmd_preview(cfg)
    if args.cmd == "report":
        return cmd_report(cfg, args.file, args.days)
    if args.cmd == "names":
        return cmd_names(cfg, args.wait, save=args.save)
    if args.cmd == "clients-undo":
        return cmd_clients_undo(cfg)
    return cmd_run(cfg)


def utf8_stdout() -> None:
    """The reports use arrows and dots that a legacy console encoding can't print."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


def cmd_names(cfg: Config, wait: float, api=None, probe=discover, save: bool = False) -> int:
    """Suggest names for Pi-hole's devices from mDNS/SSDP/NetBIOS (and nmap). Writes nothing unless --save, which
    stores the probe names in the detector's own names file (never in Pi-hole)."""
    api = api or PiholeApi(cfg.pihole_url, cfg.pihole_password)
    try:
        devices = [d for d in api.devices() if d.is_real_mac]
    finally:
        api.logout()
    found = probe([ip for d in devices if (ip := ipv4_of(d))], wait, **nmap_options(cfg))
    utf8_stdout()
    print(build_names_report(devices, read_client_comments(cfg.gravity_db), found), end="")
    if save:
        best = {d.hwaddr: choice for d in devices if (choice := best_probe(found.get(ipv4_of(d), {})))}
        store = NameStore(cfg.names_file)
        changes = store.update(best, time.time())
        store.save()
        print("\n".join([f"Saved {len(best)} name(s) to {cfg.names_file}",
                         *(f"  {mac}: {old or '(none)'} -> {new}" for mac, old, new in changes)]))
    return 0


def cmd_clients_undo(cfg: Config, api=None) -> int:
    """Reverse the newest rotation sync not yet undone: remove the MAC it added, re-add those it removed."""
    change, why_not = clientlog.pick(clientlog.read(cfg.client_changes_path))
    if not change:
        print(why_not)
        return 1
    api = api or PiholeApi(cfg.pihole_url, cfg.pihole_password)
    try:
        clientlog.undo(change, api, cfg.client_changes_path, time.time())
    finally:
        if hasattr(api, "logout"):
            api.logout()
    print(f"undone: removed {change['added']['mac']}, restored "
          f"{', '.join(e['mac'] for e in change['deleted']) or 'nothing'} ({change['name']})")
    return 0


def cmd_report(cfg: Config, file: str | None, days: float) -> int:
    """Print the shadow-week review. Reads the alerts file only; sends nothing."""
    path = Path(file or cfg.alerts_path)
    end = time.time()
    start = end - days * 86400
    if path.exists():
        records, skipped = load_records(path, start, end)
    elif file:
        print(f"no such alerts file: {path}", file=sys.stderr)
        return 1
    else:
        records, skipped = [], 0
    comments = read_client_comments(cfg.gravity_db)
    store = NameStore(cfg.names_file)
    records = relabel(records, lambda mac: comments.get(mac) or store.name(mac))
    utf8_stdout()
    print(build_report(records, start, end, push_cap=cfg.push_cap_per_hour, skipped=skipped), end="")
    return 0


def cmd_preview(cfg: Config, tg=None, state=None) -> int:
    """Send a sample alert and a sample daily report, clearly marked as examples. With the bot on, the
    sample carries real buttons (its domain is under .example, which never resolves, so Block is harmless)."""
    tg = tg or Telegram(cfg.telegram_token, cfg.telegram_chat_id, 1)
    now = time.time()
    sample = Alert(
        time=now, severity="HIGH", rule="ti_match", client="Pixel 6 Pro", domain="login.evil-c2.example",
        address="192.0.2.30 · 02:00:00:00:00:30", dedup="ti_match|example|evil-c2.example",
        message="example", evidence={"matched": "evil-c2.example", "block": block_hint("evil-c2.example")},
    )
    buttons = None
    if cfg.bot_enabled:
        own = state is None
        state = state or State(cfg.state_db)
        buttons = alert_buttons(state, sample, now)
        state.commit()
        if own:
            state.close()
    report = build_digest([
        {**sample.to_dict()},
        {"severity": "MEDIUM", "rule": "beaconing", "client": "AswinPC", "domain": "checkin.example",
         "evidence": {"interval_s": 60}, "time": now},
        {"severity": "LOW", "rule": "device_silent", "client": "iPad", "evidence": {"hours": 26}, "time": now},
    ], {"queries": 31204}, start=now - 86400, end=now)
    banner = "🧪 <i>Example - not a real alert</i>\n\n"
    ok = tg.send(banner + format_push(sample, hint=not buttons), now, capped=False, buttons=buttons)
    ok = tg.send(banner + report, now, capped=False) and ok
    print("sent" if ok else "FAILED (see log)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
