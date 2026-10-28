"""Configuration from environment variables. Every threshold is tunable without a rebuild."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, fields

DEFAULT_NOISY_APEXES = (
    # Large CDNs/platforms that legitimately produce many unique subdomains or periodic lookups.
    "googlevideo.com", "gvt1.com", "gvt2.com", "1e100.net", "googleapis.com", "googleusercontent.com",
    "akamaihd.net", "akamaiedge.net", "akamai.net", "cloudfront.net", "amazonaws.com", "fastly.net",
    "apple.com", "icloud.com", "aaplimg.com", "microsoft.com", "windows.com", "live.com", "msn.com",
    "azureedge.net", "trafficmanager.net", "steamcontent.com", "netflix.com", "nflxvideo.net",
    "in-addr.arpa", "ip6.arpa", "local", "lan", "home.arpa",
)


def _csv(value: str) -> tuple[str, ...]:
    return tuple(v.strip().lower() for v in value.split(",") if v.strip())


@dataclass
class Config:
    pihole_url: str = "http://127.0.0.1:8081"
    pihole_password: str = field(default="", repr=False)
    gravity_db: str = "/pihole/gravity.db"
    threat_list_match: str = "tif"          # substring of the adlist URL(s) treated as threat intel
    iot_group: str = "IoT"
    threat_file: str = ""                   # optional extra threat domains, one per line
    extra_iot_clients: tuple[str, ...] = ()  # optional extra IoT MACs/IPs (comma separated)
    state_db: str = "/data/state.db"
    alerts_path: str = "/data/alerts.jsonl"
    names_file: str = "/data/names.json"     # names found by `names --save` and the weekly discovery
    discovery_weekday: int = 0               # Monday (0-6): discovery runs just before that day's report
    discovery_wait: float = 10.0             # seconds to listen for replies
    rotation_probe_wait: float = 3.0         # a new private MAC is asked its name, to spot a rotated MAC
    nmap_enabled: bool = True                # discovery also nmaps the devices the other probes left unnamed
    nmap_exclude: tuple[str, ...] = ()       # IPs nmap must never touch (comma separated)
    rotation_sync: bool = False              # follow a rotated private MAC in Pi-hole Clients (adds/deletes!)
    rotation_keep: int = 2                   # MACs kept per device: the most recently seen ones
    client_changes_path: str = "/data/client_changes.jsonl"  # every Clients change, for clients-undo
    pihole_changes_path: str = "/data/pihole_changes.jsonl"  # every change made from Telegram
    telegram_token: str = field(default="", repr=False)
    telegram_chat_id: str = ""
    push_enabled: bool = False              # shadow mode by default
    bot_enabled: bool = False               # answer the owner's commands and button presses
    health_push_enabled: bool = True        # "Pi-hole API unreachable" is pushed even in shadow mode
    digest_hour: int = 9
    poll_seconds: float = 3.0
    devices_seconds: float = 60.0
    intel_seconds: float = 600.0
    fail_threshold: int = 3
    dedup_hours: float = 6.0                # HIGH: pushed again if it is still happening after this
    digest_dedup_hours: float = 168.0       # MEDIUM/LOW only reach the daily digest; once a week is enough
    push_cap_per_hour: int = 20
    learning_days: float = 7.0
    shared_clients: int = 3                 # an apex in this many clients' baselines is infrastructure
    nxdomain_window: float = 300.0
    nxdomain_threshold: int = 20
    tunnel_window: float = 600.0
    tunnel_unique_subdomains: int = 50
    tunnel_long_label: int = 40
    tunnel_long_label_count: int = 10
    tunnel_txt_count: int = 30
    beacon_min_hits: int = 10
    beacon_max_cv: float = 0.1
    beacon_min_interval: float = 30.0
    beacon_max_interval: float = 3600.0
    silent_hours: float = 24.0
    silent_min_queries: int = 50
    noisy_apexes: tuple[str, ...] = DEFAULT_NOISY_APEXES

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        cfg = cls()
        for f in fields(cls):
            raw = env.get(f.name.upper())
            if raw is None:
                continue
            setattr(cfg, f.name, parse_value(getattr(cfg, f.name), raw))
        return cfg


def parse_value(current, raw: str):
    """A setting's text, typed like its default. Raises ValueError for a malformed number."""
    raw = raw.strip()  # a CRLF .env leaves "\r" on every value; a token with it gets a 404
    if isinstance(current, bool):
        return raw.lower() in ("1", "true", "yes", "on")
    if isinstance(current, int):
        return int(raw)
    if isinstance(current, float):
        return float(raw)
    if isinstance(current, tuple):
        return _csv(raw)
    return raw


# What /set may change from Telegram: thresholds and switches. Never paths, URLs or secrets.
SETTABLE = (
    "nxdomain_window", "nxdomain_threshold", "tunnel_window", "tunnel_unique_subdomains", "tunnel_long_label",
    "tunnel_long_label_count", "tunnel_txt_count", "beacon_min_hits", "beacon_max_cv", "beacon_min_interval",
    "beacon_max_interval", "silent_hours", "silent_min_queries", "dedup_hours", "digest_hour",
    "push_cap_per_hour", "rotation_sync", "rotation_keep", "nmap_enabled", "nmap_exclude", "push_enabled",
)
BOUNDS = {"digest_hour": (0, 23), "rotation_keep": (1, 10), "push_cap_per_hour": (1, 1000)}


def parse_setting(name: str, raw: str):
    """(field, value) for /set NAME value. Raises ValueError with a reason the owner can read."""
    field_name = name.strip().lower()
    if field_name not in SETTABLE:
        raise ValueError(f"{name.upper()} can't be changed from chat")
    try:
        value = parse_value(getattr(Config(), field_name), raw)
    except ValueError:
        raise ValueError(f"{name.upper()} must be a number") from None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        low, high = BOUNDS.get(field_name, (0, float("inf")))
        if not low <= value <= high:
            limit = f"between {low} and {high}" if high != float("inf") else f"{low} or more"
            raise ValueError(f"{name.upper()} must be {limit}")
    return field_name, value


class Settings:
    """The SETTABLE values: what the .env file gave, with the /set values saved in state.db on top.

    The only thing that changes the config while running. Everything reads the one shared Config, so a
    change takes effect everywhere at once; nothing may keep its own copy of a SETTABLE value.
    """

    def __init__(self, cfg: Config, state):
        self.cfg, self.state = cfg, state
        self._env = {name: getattr(cfg, name) for name in SETTABLE}  # what /unset goes back to
        self.applied = []  # names whose saved value was put on top, for the startup log
        for name in SETTABLE:
            raw = state.get(_key(name))
            if raw is None:
                continue
            try:
                setattr(cfg, *parse_setting(name, raw))
                self.applied.append(name.upper())
            except ValueError:
                continue

    def set(self, name: str, raw: str):
        """Change one setting now and after restarts; returns the value. ValueError says why not."""
        field_name, value = parse_setting(name, raw)
        self.state.put(_key(field_name), raw)
        setattr(self.cfg, field_name, value)
        return value

    def unset(self, name: str):
        """Back to the .env value; returns it. ValueError for a name that can't be changed."""
        field_name = name.strip().lower()
        if field_name not in SETTABLE:
            raise ValueError(f"{name.upper()} can't be changed from chat")
        self.state.put(_key(field_name), None)
        setattr(self.cfg, field_name, self._env[field_name])
        return self._env[field_name]

    def items(self):
        """(NAME, value, set from chat?) for every setting /set can change."""
        return [(name.upper(), getattr(self.cfg, name), self.state.get(_key(name)) is not None)
                for name in SETTABLE]


def _key(name: str) -> str:
    return f"setting:{name.upper()}"
