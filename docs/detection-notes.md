# Detection notes

How each heuristic is calibrated, and why it is shaped the way it is. Every threshold is an
environment variable; the values below are starting points for the shadow week, not tuned truth.

## Data source

FTL v6 `/api/queries` is polled every 3 s with `from=<last seen - 2 s>`; overlap is removed
by query identity. The API returns newest-first, so longer ranges are paged *backwards* by
moving `until`, not via `cursor`/`start` (their interaction is under-documented). Query rows do
**not** contain a MAC address. `/api/network/devices` is polled every 60 s to map IP → MAC, so
baselines follow a device across DHCP changes.

## Registrable domain (apex)

Splitting uses the vendored Public Suffix List, **ICANN section only**. With the private section,
`d1x9k2q.cloudfront.net` would be its own registrable domain, so every CDN customer hash would
look like a DGA name and every CloudFront customer like a separate tunneling target.
Refresh with `curl -o src/pihole_detector/data/public_suffix_list.dat https://publicsuffix.org/list/public_suffix_list.dat`.

## Threat intel (`ti_match`)

The list is read from `gravity.db` (adlists whose URL contains `tif`) and reloaded when the
file changes. The detector does its own matching instead of relying on Pi-hole's `list_id`,
because a list attached to only one Pi-hole group (for example `IoT`) never blocks other clients'
lookups, and an "it was blocked" signal would never fire for them. Entries match their
subdomains, as in HaGeZi's *wildcard* lists. CNAME targets are checked too.

## Randomness (`dga_single`, `nxdomain_burst`)

`looks_random` scores the registrable label only (`example` in `www.example.co.uk`):

- length ≥ 10 (8 for bursts), not punycode;
- Shannon entropy ≥ **0.8 × log2(length)**. A fixed threshold is wrong: a 12-character string
  can never exceed log2(12) ≈ 3.58 bits, so the first version (≥ 3.5) flagged only 25 of 200
  truly random 12-character labels;
- plus at least one of: ≥15 % digits, <25 % vowels, or a run of ≥5 consonants
  (`y` counts as a vowel, otherwise `crashlytics` matches).

Measured on seeded random labels of 10–18 characters: 92 % of alphanumeric and 69 % of
alphabetic labels flagged. On 104 common brand/CDN labels: no hits at the `dga_single` length
(≥10); at the burst length (≥8) `appsflyer` and `freshdesk` match. That is acceptable only
because a burst needs 20 *distinct* such names answered NXDOMAIN.

- Single-label names are ignored. At startup Chrome resolves three random single-label names
  to detect resolvers that hijack NXDOMAIN, and those would otherwise look exactly like DGA output.
- `dga_single` ignores NXDOMAIN answers: during a DGA burst every failed name would otherwise
  add its own alert. `nxdomain_burst` covers failed lookups as one alert per client, and the
  name that does resolve is the one worth a MEDIUM.

## Tunneling

This rule counts per (client, apex) over a 10-minute sliding window. Large platforms legitimately
fan out across thousands of subdomains (`*.googlevideo.com` for YouTube, CDNs, Apple, Microsoft),
so `NOISY_APEXES` exempts them. **Setting `NOISY_APEXES` replaces the default list instead of
extending it**, so copy the defaults from `config.py` when overriding.

## Beaconing

The rule fires on ≥10 intervals with a mean between 30 s and 1 h and a coefficient of variation
≤ 0.1. DNS caching makes many legitimate lookups periodic (they recur roughly every TTL), so
three exclusions matter more than the threshold:

1. blocked queries (ad/telemetry SDKs retry blocked names on a timer);
2. apexes present in more than 2 clients' baselines (OS connectivity checks, NTP);
3. client→apex relationships older than the learning period (IoT heartbeats to their own
   cloud). With `seed`, this applies from day one.

A + AAAA lookups less than 2 s apart count as one event.

## Device rules

- `new_device`: the first device snapshot is recorded silently. FTL's `ip-<addr>`
  placeholders (shown when it cannot see MACs, e.g. in Docker bridge mode) are ignored. Expect
  hits from **private/rotating Wi-Fi MACs** (iOS, Android, Windows): a known phone that
  rotates its address shows up as "new". That is why this rule may be downgraded after the
  shadow week.
- `iot_off_baseline`: clients in the Pi-hole group named by `IOT_GROUP` (by MAC). It stays
  silent until the client has been seen for `LEARNING_DAYS`; every apex seen during learning
  becomes baseline.
- `device_silent`: needs ≥50 lifetime queries, alerts once per silence.

## Known blind spots

- Devices with hard-coded DNS (IP cameras and DVRs often do this) never reach Pi-hole.
- DoH/DoT clients send only their bootstrap lookup, if that, to Pi-hole.
- A single slow beacon (hours apart), or one domain per day per client, stays below every
  window.
- Restarting loses the in-memory windows (tunneling, bursts, beacon timing). Baselines and
  dedup are kept in SQLite.
