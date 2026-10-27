"""Core data types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

HIGH, MEDIUM, LOW = "HIGH", "MEDIUM", "LOW"


@dataclass(frozen=True)
class Query:
    id: int
    time: float
    domain: str
    type: str
    status: str | None
    reply: str | None
    client_ip: str
    client_name: str | None = None
    list_id: int | None = None
    cname: str | None = None

    @property
    def key(self) -> tuple:
        """Identity for de-duplicating overlapping polls (id alone is 0 in synthetic data)."""
        return (self.id, self.time, self.client_ip, self.domain, self.type)

    @classmethod
    def from_api(cls, item: dict) -> "Query":
        """Build from one element of FTL v6 `/api/queries` -> `queries[]`."""
        client = item.get("client") or {}
        reply = item.get("reply") or {}
        return cls(
            id=int(item.get("id") or 0),
            time=float(item["time"]),
            domain=(item.get("domain") or "").rstrip(".").lower(),
            type=item.get("type") or "",
            status=item.get("status"),
            reply=reply.get("type"),
            client_ip=client.get("ip") or "",
            client_name=client.get("name"),
            list_id=item.get("list_id"),
            cname=item.get("cname"),
        )


@dataclass(frozen=True)
class Device:
    """One entry of `/api/network/devices`."""

    hwaddr: str
    ips: tuple[str, ...]
    first_seen: float
    vendor: str | None = None
    name: str | None = None

    @classmethod
    def from_api(cls, item: dict) -> "Device":
        ips = item.get("ips") or []
        name = next((ip.get("name") for ip in ips if ip.get("name")), None)
        return cls(
            hwaddr=(item.get("hwaddr") or "").lower(),
            ips=tuple(ip["ip"] for ip in ips if ip.get("ip")),
            first_seen=float(item.get("firstSeen") or 0),
            vendor=item.get("macVendor") or None,
            name=name,
        )

    @property
    def is_real_mac(self) -> bool:
        # FTL uses "ip-<addr>" placeholders when it cannot see a MAC (e.g. bridge networking).
        return len(self.hwaddr) == 17 and self.hwaddr != "00:00:00:00:00:00"

    @property
    def is_private_mac(self) -> bool:
        # Locally administered bit: the per-network / rotating Wi-Fi addresses phones and tablets use.
        return self.is_real_mac and int(self.hwaddr[:2], 16) & 2 == 2


@dataclass(frozen=True)
class Alert:
    time: float
    severity: str
    rule: str
    client: str
    domain: str
    message: str
    evidence: dict = field(default_factory=dict)
    dedup: str = ""
    address: str = ""   # "ip · mac" of the client, for messages that show a friendly name

    def to_dict(self) -> dict:
        return asdict(self)
