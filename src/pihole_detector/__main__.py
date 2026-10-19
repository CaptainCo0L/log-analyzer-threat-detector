"""CLI: `python -m pihole_detector run | replay FILE | seed | digest`."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from pathlib import Path

from .config import Config
from .detector import Detector
from .intel import GravityIntel
from .sinks import JsonlSink, Telegram
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
                det.telegram.send(f"Pi-hole API reachable again after {int(now - down_since)} s.", now, capped=False)
            failures, down_since = 0, None
        except ApiError as exc:
            failures += 1
            det.stats["api_failures"] += 1
            down_since = down_since or now
            log.warning("poll failed (%d in a row): %s", failures, exc)
            if failures == cfg.fail_threshold and cfg.health_push_enabled:
                det.telegram.send(
                    f"Pi-hole API unreachable ({failures} polls in a row): {exc}. "
                    "Pi-hole is the LAN's only DNS - check that LAN DNS still resolves.", now, capped=False)
        det.tick(now)
        det.state.commit()
        time.sleep(cfg.poll_seconds)

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
            "Pi-hole detector: test message. Pushes are " + ("ON" if cfg.push_enabled else "OFF (shadow mode)"),
            time.time(), capped=False)
        print("sent" if ok else "FAILED (see log)")
        return 0 if ok else 1
    return cmd_run(cfg)


if __name__ == "__main__":
    sys.exit(main())
