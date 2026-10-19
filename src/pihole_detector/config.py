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
    telegram_token: str = field(default="", repr=False)
    telegram_chat_id: str = ""
    push_enabled: bool = False              # shadow mode by default
    health_push_enabled: bool = True        # "Pi-hole API unreachable" is pushed even in shadow mode
    digest_hour: int = 9
    poll_seconds: float = 3.0
    devices_seconds: float = 60.0
    intel_seconds: float = 600.0
    fail_threshold: int = 3
    dedup_hours: float = 6.0
    push_cap_per_hour: int = 20
    learning_days: float = 7.0
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
            current = getattr(cfg, f.name)
            if isinstance(current, bool):
                value = raw.strip().lower() in ("1", "true", "yes", "on")
            elif isinstance(current, int):
                value = int(raw)
            elif isinstance(current, float):
                value = float(raw)
            elif isinstance(current, tuple):
                value = _csv(raw)
            else:
                value = raw
            setattr(cfg, f.name, value)
        return cfg
