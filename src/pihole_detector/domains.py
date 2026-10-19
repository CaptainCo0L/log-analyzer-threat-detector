"""Domain helpers: registrable-domain splitting (Public Suffix List) and randomness scores."""

from __future__ import annotations

import math
from collections import Counter
from functools import lru_cache
from pathlib import Path

PSL_PATH = Path(__file__).parent / "data" / "public_suffix_list.dat"
VOWELS = set("aeiouy")  # 'y' as a vowel: otherwise "crashlytics" has a 6-consonant run


class PublicSuffixList:
    """Minimal PSL matcher (ICANN section only).

    Private-section suffixes such as cloudfront.net are deliberately ignored: with them,
    `d1x9k2q.cloudfront.net` would be its own registrable domain and look like a DGA name.
    """

    def __init__(self, lines):
        self.rules: set[str] = set()
        self.wildcards: set[str] = set()
        self.exceptions: set[str] = set()
        for raw in lines:
            line = raw.strip()
            if "===BEGIN PRIVATE DOMAINS===" in line:
                break
            if not line or line.startswith("//"):
                continue
            rule = line.split()[0].lower()
            if rule.startswith("!"):
                self.exceptions.add(rule[1:])
            elif rule.startswith("*."):
                self.wildcards.add(rule[2:])
            else:
                self.rules.add(rule)

    @classmethod
    def load(cls, path: Path = PSL_PATH) -> "PublicSuffixList":
        with open(path, encoding="utf-8") as handle:
            return cls(handle)

    def suffix_len(self, labels: list[str]) -> int:
        """Number of trailing labels forming the public suffix (at least 1)."""
        for i in range(len(labels)):
            candidate = ".".join(labels[i:])
            if candidate in self.exceptions:
                return len(labels) - i - 1
            if candidate in self.rules:
                return len(labels) - i
            parent = ".".join(labels[i + 1 :])
            if i + 1 < len(labels) and parent in self.wildcards:
                return len(labels) - i
        return 1

    def registrable(self, domain: str) -> str:
        """eTLD+1, e.g. `a.b.example.co.uk` -> `example.co.uk`. Returns the input for bare suffixes."""
        labels = normalise(domain).split(".")
        n = self.suffix_len(labels)
        if len(labels) <= n:
            return ".".join(labels)
        return ".".join(labels[-(n + 1) :])


@lru_cache(maxsize=1)
def default_psl() -> PublicSuffixList:
    return PublicSuffixList.load()


def normalise(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


def apex(domain: str) -> str:
    return default_psl().registrable(domain)


def subdomain_part(domain: str) -> str:
    """Everything left of the registrable domain ('' if none)."""
    name, reg = normalise(domain), apex(domain)
    return name[: -len(reg)].rstrip(".") if name != reg else ""


def registrable_label(domain: str) -> str:
    """The label just left of the public suffix: `example` for `www.example.co.uk`."""
    return apex(domain).split(".")[0]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def longest_consonant_run(text: str) -> int:
    best = run = 0
    for ch in text:
        if ch.isalpha() and ch not in VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def looks_random(label: str, min_len: int = 10, entropy_ratio: float = 0.8) -> bool:
    """Heuristic DGA test on a single label; see docs/detection-notes.md for the calibration.

    Entropy is compared to log2(len): a fixed threshold is wrong because a 12-char string can
    never exceed log2(12) = 3.58 bits, so e.g. 3.5 flagged only 1 in 8 truly random labels.
    """
    label = label.lower()
    if len(label) < min_len or label.startswith("xn--"):
        return False
    digits = sum(ch.isdigit() for ch in label) / len(label)
    vowels = sum(ch in VOWELS for ch in label) / len(label)
    if shannon_entropy(label) < entropy_ratio * math.log2(len(label)):
        return False
    return digits >= 0.15 or vowels < 0.25 or longest_consonant_run(label) >= 5
