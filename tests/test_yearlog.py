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
