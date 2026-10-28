"""Append-only JSONL files that roll over once a year.

The live file keeps its name (alerts.jsonl). The first write dated in a new year moves it aside to
alerts-<year>.jsonl, named after the year of its first record, so the live file never grows past a
year. Readers ask `files(path, start)` for every file that can hold records from `start` on.
Years are local time (the container's TZ).
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path


def _year(ts: float) -> int:
    return time.localtime(ts).tm_year


def _first_year(path: Path) -> int | None:
    try:
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                try:
                    return _year(float(json.loads(line)["time"]))
                except (json.JSONDecodeError, KeyError, TypeError, ValueError):
                    continue
    except FileNotFoundError:
        pass
    return None


def _archive(path: Path, year: int) -> Path:
    return path.with_name(f"{path.stem}-{year}{path.suffix}")


_years: dict[Path, int | None] = {}  # live file -> the year of its first record, read once


def append(path, record: dict, sort_keys: bool = False) -> None:
    path = Path(path)
    if path not in _years or not path.exists():  # unseen, or removed behind our back
        _years[path] = _first_year(path)
    year = _years[path]
    if year is not None and year < _year(record["time"]):
        archive = _archive(path, year)
        if archive.exists():        # clock went back and forth: keep both, never overwrite
            with archive.open("a", encoding="utf-8") as handle:
                handle.write(path.read_text(encoding="utf-8"))
            path.unlink()
        else:
            path.rename(archive)
        year = None
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=sort_keys) + "\n")
    if year is None:
        _years[path] = _year(record["time"])  # this record now starts the file


def files(path, start: float = 0) -> list[Path]:
    """Archives from the year of `start` on, oldest first, then the live file if it exists."""
    path = Path(path)
    pattern = re.compile(rf"{re.escape(path.stem)}-(\d{{4}}){re.escape(path.suffix)}")
    first = _year(start) if start > 0 else 0
    years = sorted(int(m[1]) for p in path.parent.glob(f"{path.stem}-*{path.suffix}")
                   if (m := pattern.fullmatch(p.name)))
    out = [_archive(path, y) for y in years if y >= first]
    return out + [path] if path.exists() else out
