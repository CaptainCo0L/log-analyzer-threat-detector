"""Regenerate the synthetic replay fixtures: `python tests/fixtures/make_fixtures.py`.

Deterministic (seeded). Only RFC 5737 IPs, locally-administered MACs and *.example names,
plus a few well-known public hostnames for realism.
"""

from __future__ import annotations

import json
import random
import string
from pathlib import Path

HERE = Path(__file__).parent
T0 = 1_760_000_000.0
DAY, HOUR = 86400, 3600
CLIENTS = {
    "pc": ("192.0.2.10", "02:00:00:00:00:10", "pc.lan"),
    "iot": ("192.0.2.20", "02:00:00:00:00:20", None),
    "phone": ("192.0.2.30", "02:00:00:00:00:30", None),
    "laptop": ("192.0.2.40", "02:00:00:00:00:40", "laptop.lan"),
}
BROWSING = ["www.wikipedia.org", "news.example", "mail.example", "video.example", "shop.example",
            "docs.example", "maps.example", "music.example", "chat.example", "weather.example"]


def row(t, domain, who, reply="IP", status="FORWARDED", qtype="A"):
    ip, _, name = CLIENTS[who]
    return {"id": 0, "time": round(T0 + t, 6), "type": qtype, "domain": domain, "cname": None,
            "status": status, "client": {"ip": ip, "name": name}, "dnssec": "INSECURE",
            "reply": {"type": reply, "time": 5.0}, "list_id": None, "upstream": "172.16.99.53#5053"}


def devices(t, extra=()):
    items = [{"hwaddr": mac, "firstSeen": T0, "macVendor": "Example Corp",
              "ips": [{"ip": ip, "name": name}]} for ip, mac, name in CLIENTS.values()]
    items += list(extra)
    return {"_devices": items, "time": T0 + t}


def browsing(rng, who, days, per_day=24):
    out = []
    for d in range(days):
        for h in range(per_day):
            t = d * DAY + h * HOUR + rng.uniform(0, 3000)   # jitter: browsing is not periodic
            out.append(row(t, rng.choice(BROWSING), who))
    return out


def random_label(rng, n=12):
    return "".join(rng.choice(string.ascii_lowercase + string.digits) for _ in range(n))


def attack_mix() -> list[dict]:
    rng = random.Random(1)
    rows = browsing(rng, "pc", 9) + browsing(rng, "phone", 9)
    # IoT device learns its two cloud endpoints on day 0, then only those for a week.
    rows += [row(i * 600, "mqtt.vendor-cloud.example", "iot") for i in range(0, 9 * 144, 7)]
    rows += [row(30, "time.vendor-cloud.example", "iot")]
    # laptop: active on day 0, then silent forever -> device_silent
    rows += [row(i * 900, rng.choice(BROWSING), "laptop") for i in range(60)]

    a = 8 * DAY + 2 * HOUR
    rows.append(row(a, "beacon.evil-c2.example", "pc"))                                  # ti_match
    rows.append(row(a + 60, "dns.google", "phone"))                                       # doh_bypass
    rows.append(row(a + 120, f"www.{random_label(rng)}.com", "pc"))                       # dga_single
    from pihole_detector.domains import looks_random
    burst = []
    while len(burst) < 25:
        label = random_label(rng)
        if looks_random(label, min_len=8):
            burst.append(label)
    rows += [row(a + 300 + i * 4, f"{name}.net", "phone", reply="NXDOMAIN") for i, name in enumerate(burst)]  # nxdomain_burst
    rows += [row(a + 600 + i * 3, f"{random_label(rng, 20)}.exfil.example", "pc") for i in range(60)]  # tunneling
    rows += [row(a + 1200 + i * 60, "checkin.beacon-host.example", "pc") for i in range(12)]          # beaconing
    rows.append(row(a + 2400, "strange-host.example", "iot"))                             # iot_off_baseline
    rows.sort(key=lambda r: r["time"])

    out: list[dict] = [devices(0)]
    new_dev = {"hwaddr": "02:00:00:00:00:99", "firstSeen": T0 + a, "macVendor": "Unknown Vendor",
               "ips": [{"ip": "192.0.2.99", "name": None}]}
    inserted = False
    for r in rows:
        if not inserted and r["time"] >= T0 + a + 3000:
            out.append(devices(a + 3000, [new_dev]))                                       # new_device
            inserted = True
        out.append(r)
    return out


def benign_day() -> list[dict]:
    rng = random.Random(2)
    rows = browsing(rng, "pc", 1) + browsing(rng, "phone", 1) + browsing(rng, "laptop", 1)
    # OS connectivity checks: periodic, but every client does them -> prevalence skip
    for who in ("pc", "phone", "laptop"):
        rows += [row(i * 300 + 7, "connectivitycheck.example", who) for i in range(200)]
    # blocked ad retries: periodic but blocked
    rows += [row(i * 120, "ads.tracker.example", "phone", status="GRAVITY") for i in range(300)]
    # CDN fan-out: many unique subdomains, but a known noisy apex
    rows += [row(5000 + i, f"rr{i}---sn-{random_label(rng, 6)}.googlevideo.com", "phone") for i in range(120)]
    # Chrome's NXDOMAIN-hijack probe: random single labels
    rows += [row(9000 + i, random_label(rng, 10), "pc", reply="NXDOMAIN") for i in range(3)]
    rows.sort(key=lambda r: r["time"])
    return [devices(0)] + rows


def write(name: str, records: list[dict]) -> None:
    with open(HERE / name, "w", encoding="utf-8", newline="\n") as handle:
        for rec in records:
            handle.write(json.dumps(rec, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(HERE.parents[1] / "src"))
    write("attack_mix.jsonl", attack_mix())
    write("benign_day.jsonl", benign_day())
    (HERE / "threats.txt").write_text("# synthetic threat-intel list for replay\nevil-c2.example\n", encoding="utf-8")
    print("fixtures written")
