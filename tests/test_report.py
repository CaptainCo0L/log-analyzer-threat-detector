import io
import json
import sys

from pihole_detector.__main__ import main
from pihole_detector.report import build_report, load_records
from conftest import T0

START = T0 - 3600
END = START + 7 * 86400


def rec(severity, rule, t, client="AswinPC", domain="x.example", **extra):
    return {"time": T0 + t, "severity": severity, "rule": rule, "client": client, "domain": domain,
            "address": "", "message": "", "evidence": {}, **extra}


def report(records, **kw):
    return build_report(records, START, END, **kw)


def test_headline_counts_severities_and_high_per_day():
    out = report([
        rec("HIGH", "ti_match", 3000), rec("HIGH", "ti_match", 3500),
        rec("HIGH", "tunneling", 4000), rec("HIGH", "tunneling", 4500),
        rec("HIGH", "ti_match", 2 * 86400),
        rec("MEDIUM", "beaconing", 100), rec("LOW", "device_silent", 200),
    ])
    assert "Alerts: 7 (5 HIGH · 1 MEDIUM · 1 LOW)" in out
    assert "HIGH per day: 0.7 average, worst day 4" in out


def test_peak_high_uses_a_sliding_hour_not_a_clock_hour():
    # Four HIGH alerts within 1500 s straddling a clock-hour boundary (T0 is 08:53:20 UTC).
    out = report([rec("HIGH", "ti_match", t) for t in (3000, 3500, 4000, 4500)], push_cap=20)
    assert "Peak HIGH in any hour: 4 of 20 push cap" in out


def section(out, title):
    """Text of one '## title' section."""
    return out.split(f"## {title}\n", 1)[1].split("\n## ", 1)[0]


def test_rule_table_counts_distinct_devices_and_domains_noisiest_first():
    out = report([
        rec("MEDIUM", "beaconing", 10, client="TV", domain="a.example"),
        rec("MEDIUM", "beaconing", 20, client="TV", domain="a.example"),
        rec("MEDIUM", "beaconing", 30, client="TV", domain="b.example"),
        rec("MEDIUM", "beaconing", 40, client="PC", domain="b.example"),
        rec("HIGH", "ti_match", 50, client="Phone", domain="evil.example"),
    ])
    rows = [r for r in section(out, "By rule").splitlines() if r.startswith("| ") and "---" not in r][1:]
    assert rows == ["| beaconing | MEDIUM | 4 | 2 | 2 |", "| ti_match | HIGH | 1 | 1 | 1 |"]


def test_repeat_offenders_are_top_ten_with_first_and_last_seen():
    records = [rec("MEDIUM", "beaconing", t, client="TV", domain="tick.example") for t in (100, 200, 300)]
    records.append(rec("MEDIUM", "beaconing", 400, client="PC", domain="once.example"))
    records += [rec("LOW", "new_device", 500 + i, client=f"dev{i}", domain=f"d{i}.example") for i in range(12)]
    rows = [r for r in section(report(records), "Repeat offenders").splitlines()
            if r.startswith("| ") and "---" not in r][1:]
    assert len(rows) == 10
    assert rows[0].startswith("| TV | beaconing | tick.example | 3 |")
    assert rows[1].startswith("| PC | beaconing | once.example | 1 |")  # ties keep first-seen order


def test_high_alerts_listed_in_full_with_address_but_medium_is_not():
    out = report([
        rec("HIGH", "ti_match", 100, client="Pixel", domain="evil.example", address="192.0.2.30 · 02:00:00:00:00:30",
            message="on a threat list"),
        rec("MEDIUM", "beaconing", 200, client="TV", domain="tick.example", address="192.0.2.40 · 02:00:00:00:00:40"),
    ])
    high = section(out, "HIGH alerts")
    assert "Pixel" in high and "192.0.2.30 · 02:00:00:00:00:30" in high
    assert "evil.example" in high and "ti_match" in high and "on a threat list" in high
    assert "tick.example" not in high and "02:00:00:00:00:40" not in out


def test_no_alerts_gives_a_short_report():
    out = report([])
    assert "No alerts in this window." in out
    assert "## By rule" not in out


def test_skipped_lines_are_reported():
    assert "2 unreadable lines skipped" in report([rec("LOW", "new_device", 1)], skipped=2)
    assert "skipped" not in report([rec("LOW", "new_device", 1)])


def test_flags_when_peak_reaches_the_push_cap():
    hits = [rec("HIGH", "ti_match", i) for i in range(5)]
    assert "reaches the push cap" in report(hits, push_cap=5)
    assert "reaches the push cap" not in report(hits, push_cap=6)


def write_alerts(path, records, junk=()):
    lines = [json.dumps(r) for r in records] + list(junk)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_load_records_keeps_only_the_window_and_counts_unreadable_lines(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [rec("HIGH", "ti_match", 0), rec("LOW", "new_device", -10 * 86400)],
                 junk=["{not json", '{"no_time": true}'])
    records, skipped = load_records(path, START, END)
    assert [r["rule"] for r in records] == ["ti_match"]
    assert skipped == 2


def test_cli_report_prints_markdown_for_the_file(tmp_path, capsys):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [rec("HIGH", "ti_match", 0, client="Pixel", domain="evil.example")])
    assert main(["report", "--file", str(path), "--days", "3650"]) == 0
    out = capsys.readouterr().out
    assert "## Push decision" in out and "Pixel" in out and "evil.example" in out


def test_cli_report_days_limits_the_window(tmp_path, capsys):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [rec("HIGH", "ti_match", 0)])  # months before the real clock
    assert main(["report", "--file", str(path), "--days", "1"]) == 0
    assert "No alerts in this window." in capsys.readouterr().out


def test_cli_report_missing_explicit_file_is_an_error(tmp_path, capsys):
    assert main(["report", "--file", str(tmp_path / "nope.jsonl")]) == 1
    assert "nope.jsonl" in capsys.readouterr().err


def test_cli_report_missing_default_file_is_an_empty_report(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("ALERTS_PATH", str(tmp_path / "data" / "alerts.jsonl"))
    assert main(["report"]) == 0
    assert "No alerts in this window." in capsys.readouterr().out


def test_cli_report_survives_a_legacy_console_encoding(tmp_path, monkeypatch):
    path = tmp_path / "alerts.jsonl"
    write_alerts(path, [rec("HIGH", "ti_match", 0)])
    raw = io.BytesIO()
    console = io.TextIOWrapper(raw, encoding="cp1252", write_through=True)
    monkeypatch.setattr(sys, "stdout", console)
    assert main(["report", "--file", str(path), "--days", "3650"]) == 0
    assert "→" in raw.getvalue().decode("utf-8")
