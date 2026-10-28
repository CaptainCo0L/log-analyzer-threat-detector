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
| `new_device` | HIGH | a MAC address appears that has never been seen before (LOW when it is a known device back on a new private Wi-Fi MAC: it answers over mDNS/Bonjour with a name already saved for another MAC, the same rule rotation sync uses) |
| `dga_single` | MEDIUM | a random-looking domain *resolved* (not blocked, not shared by 3+ devices, not part of the device's baseline) |
| `beaconing` | MEDIUM | a client past its learning week resolves the same new name at a near-constant interval |
| `iot_off_baseline` | MEDIUM | a device in the Pi-hole `IoT` group queries an apex it never used during its 7-day learning period, and Pi-hole didn't block it |
| `doh_bypass` | MEDIUM | a client resolves a public DoH/DoT resolver hostname |
| `device_silent` | LOW | an active client has sent no queries for 24 h |

See [docs/detection-notes.md](docs/detection-notes.md) for how each heuristic was calibrated and its known false positives.

## Alert routing

- **Every alert** → `alerts.jsonl`, deduplicated per (rule, client, apex): 6 h for HIGH,
  7 days for MEDIUM/LOW (`DIGEST_DEDUP_HOURS`), since those only reach the daily digest.
  The file rolls over yearly: the first alert of a new year moves last year's to
  `alerts-2026.jsonl` beside it. The digest, `/report`, `/whois` and `report` read across both.
  `pihole_changes.jsonl` rolls over the same way.
- **HIGH** → Telegram immediately, capped at 20 per hour (then one "muted" notice).
- **MEDIUM / LOW** → the daily 09:00 digest. The digest is **always** sent, even when empty, so
  a missing digest means the detector is down.
- **Health**: 3 failed polls in a row → "Pi-hole API unreachable". Pi-hole is the LAN's only
  DNS server, so this doubles as a LAN DNS outage alarm. A recovery message follows.

New deployments start in **shadow mode** (`PUSH_ENABLED=false`): alerts go only to JSONL and the
digest, so thresholds can be tuned before anything pings a phone.

### Telegram commands (`BOT_ENABLED=true`)

The bot also answers you. It long-polls Telegram (no webhook, no open port) and replies only in
your private chat: an update counts only when both its chat and its sender are `TELEGRAM_CHAT_ID`.

| Command | Answer |
| --- | --- |
| `/status` | Pi-hole up and blocking, detector uptime, lookups and alerts since the last report |
| `/report [days]` | Alert summary for 1-30 days (default 7); **📄 Full report** sends it as a `.md` file |
| `/devices [all]` | Devices that queried in the last 15 min, with name, IP and Pi-hole groups |
| `/whois <name, IP or MAC>` | One device: MAC, name source, groups, top 10 domains of the last 24 h, last 5 alerts |

It can also change Pi-hole (each reply has **↩️ Undo**, and every change is logged to
`data/pihole_changes.jsonl`):

| Command | Change |
| --- | --- |
| `/block <domain>` · `/block exact <domain>` | Deny the domain's apex and all subdomains (regex), or only that exact name |
| `/allow <domain>` · `/allow wild <domain>` | Allow that exact name, or the apex and all subdomains |
| `/unblock <domain>` · `/unallow <domain>` | Remove the exact and wildcard entries for that domain |
| `/pause [minutes]` · `/resume` | Pause blocking for 1-60 min (default 5). Pi-hole's own timer turns it back on |
| `/name <device> <name>` | Set the device's Clients comment (creates the entry in Default if it has none) |
| `/group <device> <group> [remove]` | Add the device to a group, keeping Default. Remove asks to confirm, and Default can't be removed |

Blocks and allows apply to everyone (Default group). A write command sent more than 5 minutes
before the bot sees it (the detector was down, say) is not run; send it again.

Alert settings:

| Command | Effect |
| --- | --- |
| `/mute [30m\|1h\|8h\|1d]` · `/unmute` | Hold instant alerts (default 1 h, at most 7 d) |
| `/quiet 23:00-07:00` · `/quiet off` | Hold instant alerts every day in that window (can cross midnight) |
| `/push on\|off` | Instant alerts on or off (`PUSH_ENABLED`) |
| `/settings` · `/set NAME value` · `/unset NAME` | Show or change thresholds: `NXDOMAIN_*`, `TUNNEL_*`, `BEACON_*`, `SILENT_*`, `DEDUP_HOURS`, `DIGEST_HOUR`, `PUSH_CAP_PER_HOUR`, `ROTATION_SYNC`, `ROTATION_KEEP`, `NMAP_ENABLED`, `NMAP_EXCLUDE`, `PUSH_ENABLED` |

Held alerts are still logged, and when the mute or quiet window ends they arrive as one message
with a Block button per domain. Health and rotation messages are never held. `/set` values are
saved in `state.db` and survive restarts; `/unset` goes back to the `.env` value. Paths, URLs and
secrets can't be set from chat.

Pushed alerts carry buttons:
- **🛡 Block `<apex>`** (only when the domain resolved) adds a Pi-hole regex deny for the apex and every
  subdomain, for everyone (Default group), the same thing `pihole --wild` does.
- **🔕 Mute 24 h / 7 d** silences that rule for that device. The alerts are still logged and still in the daily report.
- **📋 Copy block command** copies the NAS command, for when the bot isn't running.

Every button reply has **↩️ Undo**. The rotation-sync message has Undo too: it reverses that change,
but only while it is the device's newest one (the same rule as `clients-undo`). The daily report has
**📄 Full report**. `python -m pihole_detector preview` sends a sample alert with working buttons; its
domain is under `.example`, which never resolves, so trying Block on it is harmless.

Buttons work once and expire after a day. `/whois` shows domain *counts* only, never the raw query
log, because bot chats are not end-to-end encrypted.

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
python -m pihole_detector names         # suggest names for Pi-hole's devices via mDNS/SSDP/NetBIOS/nmap (--wait 8); --save keeps them
```

### Device names

A router that serves no reverse DNS leaves alerts naming devices `(ip, mac)`. `names` asks each
device Pi-hole knows about for its own name (mDNS reverse lookup, Bonjour browse, SSDP, NetBIOS)
and prints a table plus a block to paste into Pi-hole's Clients comments. `names` never edits Pi-hole.
`names --save` also stores what it found in `data/names.json` (MAC → name, source, last confirmed).

A device is named, in order, by: its **Pi-hole Clients comment**, then the **saved discovered
name**, then Pi-hole's own hostname for it, then its IP. The daily report and `report` look names
up when they are displayed, by the MAC in each alert, so a name found after an alert fired still
shows; `alerts.jsonl` is never rewritten.

The running service refreshes names itself: **every Monday at report time (`DISCOVERY_WEEKDAY`,
`DIGEST_HOUR`) it probes the known devices over unicast (mDNS, SSDP, NetBIOS) and saves the
answers, then sends that day's report.** A device that does not answer keeps its previous name. If
discovery fails the report still goes out.

Devices none of those probes name are then **nmapped** (`-sT` connect scan of ports
80/443/8080/8443, `ssl-cert` and `http-title` scripts, 60 s per device, no root): an appliance's
TLS certificate or web page often carries its name (a TP-Link Deco's certificate says
`tplinkdeco.net`). Stock titles such as "WEB SERVICE", IPs and `localhost` are not used, and nmap
ranks below every other probe. `NMAP_ENABLED=false` turns it off; `NMAP_EXCLUDE` lists IPs it must
never touch. The new-device name probe never uses nmap. The service sits on Docker's bridge network, so the
multicast Bonjour browse only works from a manual run on the host network:

```bash
sudo docker run --rm --network host --env-file /mnt/Home/apps/pihole/.env \
  -e PIHOLE_URL=http://127.0.0.1:8081 -e GRAVITY_DB=/pihole/gravity.db \
  -v /mnt/Home/apps/pihole/etc-pihole:/pihole:ro -v /mnt/Home/apps/pihole-detector/data:/data \
  pihole-detector:local names --save
```

### Rotation sync (`ROTATION_SYNC=true`)

The one thing that edits Pi-hole. Phones and tablets rotate their private Wi-Fi MAC, which drops
them out of any group set by MAC. When a new private MAC answers with an **mDNS/Bonjour** name that
is saved for the device's other MACs (at join time, or in the weekly discovery if it was asleep), the
service adds the new MAC to Pi-hole Clients with the comment and **all groups** of that device's most
recently seen entry (Default is always included). It then keeps the device's `ROTATION_KEEP` (2)
most recently seen MACs and deletes the older entries.

It never deletes a burned-in MAC, never acts on SSDP/NetBIOS/nmap names, and never touches an
entry that is not saved under that name. If the device's entries disagree on groups, it does nothing.
Each change goes to Telegram and to `data/client_changes.jsonl`. To reverse the latest one:

```bash
sudo docker exec pihole-detector python -m pihole_detector clients-undo
```

Any device can claim any name over mDNS, so a spoofer could take a device's groups. You would see
it on Telegram straight away.

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

To update a running install, commit and run `deploy/deploy.sh`: it backs up `data/`, replaces the code
with `HEAD` (removed files included), rebuilds and waits for the healthcheck.

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
