import json
import time

from pihole_detector import yearlog
from pihole_detector.alertlog import AlertLog


def ts(year, month=6, day=1):
    return time.mktime((year, month, day, 12, 0, 0, 0, 0, -1))


def lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_first_write_of_a_new_year_moves_the_old_file_aside(tmp_path):
    path = tmp_path / "alerts.jsonl"
    yearlog.append(path, {"time": ts(2026, 12, 31), "n": 1})
    yearlog.append(path, {"time": ts(2026, 12, 31), "n": 2})
    yearlog.append(path, {"time": ts(2027, 1, 1), "n": 3})
    assert [r["n"] for r in lines(tmp_path / "alerts-2026.jsonl")] == [1, 2]
    assert [r["n"] for r in lines(path)] == [3]


def test_an_existing_archive_is_appended_to_not_overwritten(tmp_path):
    path = tmp_path / "alerts.jsonl"
    (tmp_path / "alerts-2026.jsonl").write_text(json.dumps({"time": ts(2026), "n": 0}) + "\n", encoding="utf-8")
    yearlog.append(path, {"time": ts(2026), "n": 1})
    yearlog.append(path, {"time": ts(2027), "n": 2})
    assert [r["n"] for r in lines(tmp_path / "alerts-2026.jsonl")] == [0, 1]


def test_files_covers_the_window_oldest_first(tmp_path):
    path = tmp_path / "alerts.jsonl"
    for year in (2024, 2025, 2026):
        (tmp_path / f"alerts-{year}.jsonl").write_text("", encoding="utf-8")
    path.write_text("", encoding="utf-8")
    (tmp_path / "alerts-old.jsonl").write_text("", encoding="utf-8")   # not an archive
    assert [p.name for p in yearlog.files(path, ts(2025, 3))] == ["alerts-2025.jsonl", "alerts-2026.jsonl", "alerts.jsonl"]
    assert [p.name for p in yearlog.files(path, 0)][0] == "alerts-2024.jsonl"


def test_readers_see_last_years_alerts_after_rollover(tmp_path):
    path = tmp_path / "alerts.jsonl"
    old = {"time": ts(2026, 12, 20), "severity": "HIGH", "rule": "ti_match", "client": "Pixel"}
    new = {"time": ts(2027, 1, 2), "severity": "LOW", "rule": "new_device", "client": "TV"}
    yearlog.append(path, old)
    yearlog.append(path, new)
    assert [r["rule"] for r in AlertLog(path).read(ts(2026, 12, 1))] == ["ti_match", "new_device"]
    assert [r["rule"] for r in AlertLog(path).read(ts(2027, 1, 1))] == ["new_device"]
    assert [r["rule"] for r in AlertLog(path).read(ts(2026, 12, 1), ts(2026, 12, 31))] == ["ti_match"]


def test_telegram_changes_roll_over_too(tmp_path):
    from pihole_detector.changes import PiholeChanges, set_blocking
    from pihole_detector.config import Config
    from conftest import FakePihole
    path = tmp_path / "pihole_changes.jsonl"
    changes = PiholeChanges(Config(pihole_changes_path=str(path)), FakePihole())
    changes.apply([set_blocking(False, 300)], ts(2026, 12, 31), "/pause 5")
    changes.apply([set_blocking(True)], ts(2027, 1, 1), "/resume")
    assert [r["command"] for r in lines(tmp_path / "pihole_changes-2026.jsonl")] == ["/pause 5"]
    assert [r["command"] for r in lines(path)] == ["/resume"]


def test_report_reads_last_years_archive_when_the_live_file_is_gone(tmp_path, capsys):
    from pihole_detector.__main__ import main
    archive = tmp_path / "alerts-2026.jsonl"
    archive.write_text(json.dumps({"time": time.time() - 3600, "severity": "HIGH", "rule": "ti_match",
                                   "client": "Pixel", "domain": "evil.example"}) + "\n", encoding="utf-8")
    assert main(["report", "--file", str(tmp_path / "alerts.jsonl"), "--days", "1"]) == 0
    assert "evil.example" in capsys.readouterr().out


def test_a_live_file_removed_between_writes_is_read_again(tmp_path):
    path = tmp_path / "alerts.jsonl"
    yearlog.append(path, {"time": ts(2026), "n": 1})
    path.unlink()                                   # e.g. `replay` starts a fresh output file
    yearlog.append(path, {"time": ts(2027), "n": 2})
    yearlog.append(path, {"time": ts(2027), "n": 3})
    assert not (tmp_path / "alerts-2026.jsonl").exists() and [r["n"] for r in lines(path)] == [2, 3]
