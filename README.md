# Pi-hole DNS Threat Detector

Real-time threat detection for a home network, using the DNS queries that a
[Pi-hole](https://pi-hole.net) v6 resolver already sees. It polls the FTL REST API every few
seconds, runs a set of detection rules, writes every alert to a JSONL audit trail, pushes HIGH
alerts to Telegram and sends a daily digest.

> **Scope.** The detector only reads: the Pi-hole API and (read-only) `gravity.db`. It never
> changes Pi-hole configuration, blocks anything or touches the network. Alerts are **triage
> signals for a human, not proof of compromise.** Each alert carries the exact command to block
> the domain by hand.

## Why DNS

Every device on the LAN, including phones, TVs and IoT that will never run an endpoint agent,
has to resolve names. With Pi-hole as the only DNS server, its query log is the one sensor that
covers all of them. What it cannot see: devices using hard-coded DNS, or DoH/DoT clients
(the `doh_bypass` and `device_silent` rules exist to surface those).

## Rules

| Rule | Severity | Fires when |
|---|---|---|
| `ti_match` | HIGH | the domain, a parent or its CNAME target is on the threat-intel list (HaGeZi TIF), **whether Pi-hole blocked it or not** |
| `tunneling` | HIGH | one client sends ≥50 unique subdomains, ≥10 over-long labels or ≥30 TXT/NULL queries under one apex in 10 min |
| `nxdomain_burst` | HIGH | ≥20 distinct random-looking names answered NXDOMAIN for one client in 5 min (DGA malware searching for its C2) |
| `new_device` | HIGH | a MAC address appears that has never been seen before |
| `dga_single` | MEDIUM | a random-looking domain *resolved* |
| `beaconing` | MEDIUM | a client resolves the same new name at a near-constant interval |
| `iot_off_baseline` | MEDIUM | a device in the Pi-hole `IoT` group queries an apex it never used during its 7-day learning period |
| `doh_bypass` | MEDIUM | a client resolves a public DoH/DoT resolver hostname |
| `device_silent` | LOW | an active client has sent no queries for 24 h |

See [docs/detection-notes.md](docs/detection-notes.md) for how each heuristic was calibrated and its known false positives.

## Alert routing

- **Every alert** → `alerts.jsonl`, deduplicated per (rule, client, apex) for 6 h.
- **HIGH** → Telegram immediately, capped at 20 per hour (then one "muted" notice).
- **MEDIUM / LOW** → the daily 09:00 digest. The digest is **always** sent, even when empty, so
  a missing digest means the detector is down.
- **Health**: 3 failed polls in a row → "Pi-hole API unreachable". Pi-hole is the LAN's only
  DNS server, so this doubles as a LAN DNS outage alarm. A recovery message follows.

New deployments start in **shadow mode** (`PUSH_ENABLED=false`): alerts go only to JSONL and the
digest, so thresholds can be tuned before anything pings a phone.

## Requirements

- Pi-hole v6 (FTL REST API); developed against Pi-hole v6.4 / FTL 6.7.
- Python 3.12+, **standard library only**. `pytest` for the tests.

## Quick start (no Pi-hole needed)

Replay a synthetic attack scenario through the full pipeline:

```bash
PYTHONPATH=src THREAT_FILE=tests/fixtures/threats.txt EXTRA_IOT_CLIENTS=02:00:00:00:00:20 \
  python -m pihole_detector replay tests/fixtures/attack_mix.jsonl
```

```text
[HIGH] ti_match: pc.lan (192.0.2.10, 02:00:00:00:00:10) looked up threat-intel domain beacon.evil-c2.example (NOT blocked - resolved normally)
[MEDIUM] doh_bypass: (192.0.2.30, 02:00:00:00:00:30) resolved DoH/DoT resolver dns.google; its later lookups may bypass Pi-hole
[HIGH] nxdomain_burst: (192.0.2.30, 02:00:00:00:00:30) got NXDOMAIN for 20 random-looking names in 5 min (possible DGA malware hunting for its C2)
[HIGH] tunneling: pc.lan (192.0.2.10, 02:00:00:00:00:10) -> exfil.example: 50 unique subdomains in 10 min (possible DNS tunneling / exfiltration)
...
```

## Commands

```bash
python -m pihole_detector run           # live: poll the API, alert in real time
python -m pihole_detector seed --days 7 # backfill baselines from FTL history (no alerts)
python -m pihole_detector replay FILE   # run a JSONL fixture through the pipeline
python -m pihole_detector test-push     # send one Telegram test message
python -m pihole_detector digest        # send the digest now
python -m pihole_detector report        # Markdown review of alerts.jsonl (--days 7, --file PATH); sends nothing
python -m pihole_detector names         # suggest names for Pi-hole's devices via mDNS/SSDP/NetBIOS (--wait 8); writes nothing
```

`names` fills the gap left by a router that serves no reverse DNS: it asks each device Pi-hole
knows about for its own name and prints a table plus a block to paste into Pi-hole's Clients
comments (the detector already reads those). It never edits Pi-hole. Run it as a one-off
container on the host network so the probes reach the LAN:

```bash
sudo docker run --rm --network host --env-file /mnt/Home/apps/pihole/.env \
  -e PIHOLE_URL=http://127.0.0.1:8081 -e GRAVITY_DB=/pihole/gravity.db \
  -v /mnt/Home/apps/pihole/etc-pihole:/pihole:ro pihole-detector:local names
```

All settings are environment variables named after the fields in
[`config.py`](src/pihole_detector/config.py) (`POLL_SECONDS`, `NXDOMAIN_THRESHOLD`, …).

## Deployment (Docker, next to Pi-hole)

```bash
# on the Pi-hole host
mkdir -p /srv/pihole-detector/data && chown 1000:1000 /srv/pihole-detector/data
cp deploy/env.example /srv/pihole-detector/.env && chmod 600 /srv/pihole-detector/.env
docker compose -f deploy/compose.yml up -d --build
docker compose -f deploy/compose.yml run --rm detector seed --days 7
```

`deploy/compose.yml` is written for the author's host (paths under `/mnt/Home/apps`); adjust
the two Pi-hole paths. Notes:

- The Pi-hole password is read from Pi-hole's own `.env` via `env_file`, not copied. Creating a
  Pi-hole **app password** would log out every existing session, and v6 keeps only one.
- Mount Pi-hole's `etc-pihole` **directory** read-only, not `gravity.db` itself: gravity
  updates replace the file, and a single-file bind mount keeps the old inode.
- The healthcheck kills a wedged detector so `restart: unless-stopped` can restart it. Docker
  never restarts a container just because it is unhealthy.

## Tests

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v
```

Every rule has positive, negative and boundary tests on an injected clock. `test_replay.py`
asserts that the attack fixture raises each rule exactly once and that a synthetic benign day
raises nothing. Fixtures are generated deterministically by `tests/fixtures/make_fixtures.py`
and contain only RFC 5737 addresses, locally-administered MACs and `.example` names.
CI runs on every push (`.github/workflows/tests.yml`).

## Ethical use

Only monitor networks you own or are authorised to monitor, and tell the people whose devices
use them: a DNS log is a detailed record of their browsing. Never publish real query logs.
