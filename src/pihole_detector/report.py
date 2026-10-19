"""Shadow-week review: turn alerts.jsonl records into one Markdown report."""

from __future__ import annotations

import json
import time
from collections import Counter

from .model import HIGH, LOW, MEDIUM

HOUR = 3600


SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


def _day(ts: float) -> str:
    return time.strftime("%a %d %b", time.localtime(ts))


def _stamp(ts: float) -> str:
    return time.strftime("%a %d %b %H:%M", time.localtime(ts))


def _peak_in_hour(times: list[float]) -> int:
    """Most alerts inside any sliding one-hour window, which is how the push cap counts."""
    times = sorted(times)
    peak, lo = 0, 0
    for hi, t in enumerate(times):
        while t - times[lo] >= HOUR:
            lo += 1
        peak = max(peak, hi - lo + 1)
    return peak


def _headline(records: list[dict], start: float, end: float, push_cap: int) -> list[str]:
    by_sev = Counter(r["severity"] for r in records)
    high = [r["time"] for r in records if r["severity"] == HIGH]
    per_day = Counter(_day(t) for t in high)
    days = max((end - start) / 86400, 1e-9)
    worst_day, worst = per_day.most_common(1)[0] if per_day else ("-", 0)
    sevs = " · ".join(f"{by_sev[s]} {s}" for s in (HIGH, MEDIUM, LOW))
    peak = _peak_in_hour(high)
    lines = [
        "## Push decision",
        f"- Alerts: {len(records)} ({sevs})",
        f"- HIGH per day: {len(high) / days:.1f} average, worst day {worst} ({worst_day})",
        f"- Peak HIGH in any hour: {peak} of {push_cap} push cap",
    ]
    if peak >= push_cap:
        lines.append("- ⚠ Peak HIGH reaches the push cap: some pushes would have been dropped")
    return lines


def _by_rule(records: list[dict]) -> list[str]:
    groups: dict[str, list[dict]] = {}
    for r in records:
        groups.setdefault(r["rule"], []).append(r)
    lines = ["## By rule", "| Rule | Severity | Alerts | Devices | Domains |", "| --- | --- | ---: | ---: | ---: |"]
    for rule, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        sev = min((r["severity"] for r in items), key=lambda s: SEVERITY_ORDER.get(s, 3))
        devices = len({r["client"] for r in items})
        domains = len({r["domain"] for r in items if r.get("domain")})
        lines.append(f"| {rule} | {sev} | {len(items)} | {devices} | {domains} |")
    return lines


def _offenders(records: list[dict]) -> list[str]:
    keys = Counter((r["client"], r["rule"], r.get("domain") or "") for r in records)
    times: dict[tuple, list[float]] = {}
    for r in records:
        times.setdefault((r["client"], r["rule"], r.get("domain") or ""), []).append(r["time"])
    lines = ["## Repeat offenders", "| Device | Rule | Domain | Alerts | First seen | Last seen |",
             "| --- | --- | --- | ---: | --- | --- |"]
    for key, count in keys.most_common(10):
        lines.append(f"| {key[0]} | {key[1]} | {key[2] or '-'} | {count} | "
                     f"{_stamp(min(times[key]))} | {_stamp(max(times[key]))} |")
    return lines


def _high_alerts(records: list[dict]) -> list[str]:
    lines = ["## HIGH alerts"]
    high = sorted((r for r in records if r["severity"] == HIGH), key=lambda r: r["time"])
    if not high:
        lines.append("None.")
    for r in high:
        who = " · ".join(part for part in (r["client"], r.get("address")) if part)
        what = " ".join(part for part in (r["rule"], r.get("domain")) if part)
        message = f" - {r['message']}" if r.get("message") else ""
        lines.append(f"- {_stamp(r['time'])} · {who} · {what}{message}")
    return lines


def load_records(path, start: float, end: float) -> tuple[list[dict], int]:
    """Records inside [start, end] plus the number of lines that could not be read."""
    records, skipped = [], 0
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                record = json.loads(line)
                when = float(record["time"])
                record["severity"], record["rule"], record["client"]
            except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                skipped += 1
                continue
            if start <= when <= end:
                records.append(record)
    return records, skipped


def build_report(records: list[dict], start: float, end: float, *, push_cap: int = 20, skipped: int = 0) -> str:
    lines = ["# Pi-hole detector review", f"{_stamp(start)} → {_stamp(end)} ({(end - start) / 86400:.1f} days)", ""]
    if not records:
        lines.append("No alerts in this window.")
    else:
        for part in (_headline(records, start, end, push_cap), _by_rule(records), _offenders(records),
                     _high_alerts(records)):
            lines += part + [""]
    if skipped:
        lines.append(f"_{skipped} unreadable lines skipped._")
    return "\n".join(lines).rstrip() + "\n"
