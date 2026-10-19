"""`names`: suggest a name for every device Pi-hole knows about. Read-only."""

from __future__ import annotations

import ipaddress

SOURCES = ("mDNS", "Bonjour", "SSDP", "NetBIOS")  # best first
COMMENT = "Clients comment"


def ipv4_of(device) -> str | None:
    for ip in device.ips:
        try:
            if ipaddress.ip_address(ip).version == 4:
                return ip
        except ValueError:
            continue
    return None


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
        comment = comments.get(dev.hwaddr) or (comments.get(ip) if ip else None)
        evidence = found.get(ip, {}) if ip else {}
        probed = next(((evidence[s], s) for s in SOURCES if s in evidence), None)
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
