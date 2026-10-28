"""`names`: suggest a name for every device Pi-hole knows about. Read-only."""

from __future__ import annotations

import ipaddress
import re

SOURCES = ("mDNS", "Bonjour", "SSDP", "NetBIOS", "nmap")  # best first
COMMENT = "Clients comment"


def name_key(text: str | None) -> str:
    """A name reduced to letters and digits, so "Aswins ipad" finds "Aswins-iPad"."""
    return re.sub(r"[^a-z0-9]", "", (text or "").casefold())


def same_name(a: str | None, b: str | None) -> bool:
    """Do two names mean the same device? Every "same device" check compares names this way."""
    return bool(name_key(a)) and name_key(a) == name_key(b)


def comment_for(comments: dict[str, str], mac: str | None, ip: str | None) -> str | None:
    """The device's Pi-hole Clients comment: by MAC, then by IP."""
    return (mac and comments.get(mac)) or (ip and comments.get(ip)) or None


def is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def ipv4_of(device) -> str | None:
    return next((ip for ip in device.ips if is_ipv4(ip)), None)


def best_probe(evidence: dict[str, str]) -> tuple[str, str] | None:
    """(name, source) from the most trusted probe that answered, or None."""
    return next(((evidence[s], s) for s in SOURCES if s in evidence), None)


def _cell(text: str) -> str:
    return text.replace("|", "/")


def build_names_report(devices, comments: dict[str, str], found: dict[str, dict[str, str]]) -> str:
    """Markdown table of the best name per device, plus a copy-ready block for new names.

    comments: Pi-hole Clients comments keyed by lowercase MAC or IP.
    found: {ip: {source: name}} from the probes.
    """
    entries = []
    for dev in devices:
        if not dev.is_real_mac:
            continue
        ip = ipv4_of(dev)
        comment = comment_for(comments, dev.hwaddr, ip)
        evidence = found.get(ip, {}) if ip else {}
        probed = best_probe(evidence)
        if comment:
            name, source = comment, COMMENT
        elif probed:
            name, source = probed
        elif dev.vendor:
            name, source = f"{dev.vendor} device", "vendor guess"
        else:
            name, source = "?", "-"
        entries.append({"dev": dev, "ip": ip or "-", "name": name, "source": source, "evidence": evidence,
                        "commented": bool(comment), "probed": probed is not None})

    owners: dict[str, set[str]] = {}
    for e in entries:
        for value in e["evidence"].values():
            owners.setdefault(value.lower(), set()).add(e["dev"].hwaddr)

    def sort_key(e):
        return (0, int(ipaddress.ip_address(e["ip"]))) if e["ip"] != "-" else (1, 0)

    entries.sort(key=sort_key)
    lines = ["# Pi-hole device names", "", "## Devices", "| IP | MAC | Name | From | Evidence | Notes |",
             "| --- | --- | --- | --- | --- | --- |"]
    for e in entries:
        mac = e["dev"].hwaddr
        evidence = " · ".join(f"{s}: {e['evidence'][s]}" for s in SOURCES if s in e["evidence"]) or "-"
        notes = []
        if e["ip"] == "-":
            notes.append("no IPv4 address to probe")
        elif not e["evidence"] and not e["commented"]:
            notes.append("no answer - run again while it is on")
        for value in e["evidence"].values():
            notes += [f"same name as {other}" for other in sorted(owners[value.lower()] - {mac})
                      if f"same name as {other}" not in notes]
        lines.append(f"| {e['ip']} | {mac} | {_cell(e['name'])} | {e['source']} | {_cell(evidence)} | {'; '.join(notes)} |")

    new = [e for e in entries if e["probed"] and not e["commented"]]
    lines += ["", "## Add to Pi-hole Clients"]
    if new:
        lines += ["Add each under Pi-hole > Clients as the comment, and keep the client in the Default group:", "```"]
        lines += [f"{e['dev'].hwaddr}  {e['name']}" for e in new]
        lines.append("```")
    else:
        lines.append("Nothing new to add.")
    return "\n".join(lines) + "\n"
