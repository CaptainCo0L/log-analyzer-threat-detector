#!/usr/bin/env python3
"""Offline analyzer for common Linux SSH authentication log messages."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


IP_PATTERN = r"(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})"

FAILURE_PATTERNS = [
    re.compile(rf"Failed password for (?:invalid user )?.*? from {IP_PATTERN}\b", re.IGNORECASE),
    re.compile(rf"Invalid user .*? from {IP_PATTERN}\b", re.IGNORECASE),
]
SUCCESS_PATTERNS = [
    re.compile(rf"Accepted password for .*? from {IP_PATTERN}\b", re.IGNORECASE),
    re.compile(rf"Accepted publickey for .*? from {IP_PATTERN}\b", re.IGNORECASE),
]

TIMESTAMP_PATTERN = re.compile(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


@dataclass(frozen=True)
class SSHEvent:
    line_number: int
    timestamp: str
    source_ip: str
    outcome: str
    raw_line: str


@dataclass(frozen=True)
class Alert:
    severity: str
    rule: str
    source_ip: str
    message: str
    evidence: dict


def parse_line(line: str, line_number: int) -> SSHEvent | None:
    """Parse a supported SSH auth log line; return None for unrelated lines."""
    for outcome, patterns in (
        ("failure", FAILURE_PATTERNS),
        ("success", SUCCESS_PATTERNS),
    ):
        for pattern in patterns:
            match = pattern.search(line)
            if match:
                timestamp_match = TIMESTAMP_PATTERN.search(line)
                timestamp = timestamp_match.group(1) if timestamp_match else "unknown"
                return SSHEvent(
                    line_number=line_number,
                    timestamp=timestamp,
                    source_ip=match.group("ip"),
                    outcome=outcome,
                    raw_line=line.rstrip("\n"),
                )
    return None


def parse_log(lines: Iterable[str]) -> list[SSHEvent]:
    """Parse all recognized SSH events, preserving file order."""
    events: list[SSHEvent] = []
    for line_number, line in enumerate(lines, start=1):
        event = parse_line(line, line_number)
        if event is not None:
            events.append(event)
    return events


def analyze_events(events: list[SSHEvent], threshold: int = 5) -> list[Alert]:
    """Generate simple triage alerts from parsed events."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    failures: Counter[str] = Counter()
    last_outcome: dict[str, str] = {}
    failures_before_success: dict[str, int] = defaultdict(int)

    for event in events:
        if event.outcome == "failure":
            failures[event.source_ip] += 1
            last_outcome[event.source_ip] = "failure"
        elif event.outcome == "success":
            if last_outcome.get(event.source_ip) == "failure":
                failures_before_success[event.source_ip] = failures[event.source_ip]
            last_outcome[event.source_ip] = "success"

    alerts: list[Alert] = []
    for ip, count in sorted(failures.items()):
        if count >= threshold:
            alerts.append(
                Alert(
                    severity="HIGH",
                    rule="repeated_failed_logins",
                    source_ip=ip,
                    message=f"Repeated failed SSH logins from {ip} ({count} failures)",
                    evidence={"failed_attempts": count, "threshold": threshold},
                )
            )

    for ip, count in sorted(failures_before_success.items()):
        if count >= threshold:
            alerts.append(
                Alert(
                    severity="MEDIUM",
                    rule="success_after_repeated_failures",
                    source_ip=ip,
                    message=f"Successful SSH login from {ip} after {count} recorded failure(s)",
                    evidence={"failures_before_success": count, "threshold": threshold},
                )
            )

    return alerts


def build_summary(events: list[SSHEvent], alerts: list[Alert]) -> dict:
    failures = sum(event.outcome == "failure" for event in events)
    successes = sum(event.outcome == "success" for event in events)
    return {
        "parsed_ssh_events": len(events),
        "failed_logins": failures,
        "successful_logins": successes,
        "unique_source_ips": len({event.source_ip for event in events}),
        "alerts": [asdict(alert) for alert in alerts],
    }


def print_report(path: Path, summary: dict) -> None:
    print("Log Analyzer & Threat Detector")
    print(f"File: {path}")
    print(f"Parsed SSH events: {summary['parsed_ssh_events']}")
    print(f"Failed logins: {summary['failed_logins']}")
    print(f"Successful logins: {summary['successful_logins']}")
    print(f"Unique source IPs: {summary['unique_source_ips']}")
    print("\nALERTS")
    if not summary["alerts"]:
        print("No alerts generated.")
        return
    for alert in summary["alerts"]:
        print(f"[{alert['severity']}] {alert['message']} (rule: {alert['rule']})")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Analyze Linux SSH authentication logs for suspicious patterns."
    )
    parser.add_argument("logfile", type=Path, help="Path to an auth.log-style text file")
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Minimum failed attempts from one IP to trigger an alert (default: 5)",
    )
    parser.add_argument("--json-out", type=Path, help="Optional path to write JSON report")
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if not args.logfile.is_file():
        print(f"Error: log file not found: {args.logfile}", file=sys.stderr)
        return 2

    try:
        with args.logfile.open("r", encoding="utf-8", errors="replace") as handle:
            events = parse_log(handle)
    except OSError as exc:
        print(f"Error reading log file: {exc}", file=sys.stderr)
        return 2

    alerts = analyze_events(events, threshold=args.threshold)
    summary = build_summary(events, alerts)
    print_report(args.logfile, summary)

    if args.json_out:
        try:
            args.json_out.parent.mkdir(parents=True, exist_ok=True)
            args.json_out.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        except OSError as exc:
            print(f"Error writing JSON report: {exc}", file=sys.stderr)
            return 2
        print(f"\nJSON report written to: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
