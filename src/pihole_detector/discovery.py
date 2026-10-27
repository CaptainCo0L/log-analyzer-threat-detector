"""Name discovery for `names`: mDNS, SSDP/UPnP and NetBIOS probes, and their packet parsers."""

from __future__ import annotations

import ipaddress
import socket
import struct
import subprocess
import threading
import time
import urllib.request
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

PTR = 12
NBSTAT = 0x21
UNICAST_IN = 0x8001  # class IN with the mDNS "unicast response" bit


def reverse_name(ip: str) -> str:
    return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"


def _encode_name(name: str) -> bytes:
    return b"".join(bytes([len(part)]) + part.encode() for part in name.rstrip(".").split(".")) + b"\x00"


def build_ptr_query(name: str) -> bytes:
    return struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0) + _encode_name(name) + struct.pack(">HH", PTR, UNICAST_IN)


def _read_name(packet: bytes, pos: int) -> tuple[str, int]:
    """A DNS name at `pos`, following compression pointers. Returns (name, position after it)."""
    labels: list[str] = []
    end = None
    for _ in range(128):  # a pointer loop in a hostile packet must not spin forever
        length = packet[pos]
        if length == 0:
            return ".".join(labels), (end if end is not None else pos + 1)
        if length & 0xC0 == 0xC0:
            if end is None:
                end = pos + 2
            pos = ((length & 0x3F) << 8) | packet[pos + 1]
            continue
        labels.append(packet[pos + 1:pos + 1 + length].decode("utf-8", "replace"))
        pos += 1 + length
    raise ValueError("name too long or looping")


def parse_ptr_targets(packet: bytes) -> list[str]:
    """The target names of every PTR answer in a DNS response; garbage gives what was readable."""
    targets: list[str] = []
    try:
        _id, _flags, questions, answers, _auth, _extra = struct.unpack(">HHHHHH", packet[:12])
        pos = 12
        for _ in range(questions):
            _, pos = _read_name(packet, pos)
            pos += 4
        for _ in range(answers):
            _, pos = _read_name(packet, pos)
            rtype, _cls, _ttl, length = struct.unpack(">HHIH", packet[pos:pos + 10])
            pos += 10
            if rtype == PTR:
                targets.append(_read_name(packet, pos)[0])
            pos += length
    except (struct.error, ValueError, IndexError):
        pass
    return targets


def parse_ssdp(data: bytes) -> dict[str, str]:
    headers = {}
    for line in data.decode("latin-1").splitlines()[1:]:
        key, sep, value = line.partition(":")
        if sep:
            headers[key.strip().lower()] = value.strip()
    return headers


def parse_upnp_description(xml: str) -> dict[str, str]:
    wanted = ("friendlyName", "manufacturer", "modelName")
    found: dict[str, str] = {}
    try:
        for element in ET.fromstring(xml).iter():
            tag = element.tag.rsplit("}", 1)[-1]
            if tag in wanted and tag not in found and element.text and element.text.strip():
                found[tag] = element.text.strip()
    except ET.ParseError:
        return {}
    return found


def build_nbstat_query() -> bytes:
    # The wildcard name "*" in NetBIOS first-level encoding is "CK" followed by 30 "A"s.
    return (struct.pack(">HHHHHH", 0x1234, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
            + struct.pack(">HH", NBSTAT, 1))


def parse_nbstat(data: bytes) -> str | None:
    """The machine's own (unique, suffix 0x00) name from a NetBIOS node-status reply."""
    try:
        _id, _flags, _qd, answers, _auth, _extra = struct.unpack(">HHHHHH", data[:12])
        if not answers:
            return None
        _, pos = _read_name(data, 12)
        pos += 10
        count = data[pos]
        pos += 1
        for _ in range(count):
            name, suffix, flags = struct.unpack(">15sBH", data[pos:pos + 18])
            pos += 18
            if suffix == 0 and not flags & 0x8000:  # the group bit marks the workgroup
                return name.decode("ascii", "replace").strip() or None
    except (struct.error, ValueError, IndexError):
        pass
    return None



DEFAULT_PORTS = {"mdns": 5353, "netbios": 137, "ssdp": 1900}
MAX_DESCRIPTION = 64 * 1024
CRLF = bytes([13, 10])
SEARCH = CRLF.join([b'M-SEARCH * HTTP/1.1', b'HOST: 239.255.255.250:1900', b'MAN: "ssdp:discover"',
                    b'MX: 1', b'ST: upnp:rootdevice', b'', b''])


def _ask(packets: dict[str, bytes], port: int, wait: float) -> dict[str, bytes]:
    """Send one UDP packet to each ip and collect the first reply from each, for up to `wait` s."""
    replies: dict[str, bytes] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for ip, packet in packets.items():
            try:
                sock.sendto(packet, (ip, port))
            except OSError:
                continue
        deadline = time.monotonic() + wait
        while len(replies) < len(packets) and (left := deadline - time.monotonic()) > 0:
            sock.settimeout(left)
            try:
                data, addr = sock.recvfrom(4096)
            except TimeoutError:
                break
            except ConnectionResetError:  # Windows reports an earlier "port unreachable" this way
                continue
            except OSError:
                break
            replies.setdefault(addr[0], data)
    return replies


def probe_mdns(ips, wait, port=DEFAULT_PORTS["mdns"]) -> dict[str, str]:
    """Reverse-PTR each ip over unicast; Apple devices, TVs and printers answer with their .local name."""
    found = {}
    for ip, data in _ask({ip: build_ptr_query(reverse_name(ip)) for ip in ips}, port, wait).items():
        host = next((t for t in parse_ptr_targets(data) if t.lower().endswith(".local")), None)
        if host:
            found[ip] = host[: -len(".local")]
    return found


def probe_netbios(ips, wait, port=DEFAULT_PORTS["netbios"]) -> dict[str, str]:
    found = {}
    for ip, data in _ask({ip: build_nbstat_query() for ip in ips}, port, wait).items():
        name = parse_nbstat(data)
        if name:
            found[ip] = name
    return found


def _http_get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=3) as response:  # noqa: S310 - http LAN url, checked by the caller
        return response.read(MAX_DESCRIPTION).decode("utf-8", "replace")


def probe_ssdp(ips, wait, port=DEFAULT_PORTS["ssdp"], fetch=_http_get) -> dict[str, str]:
    """Unicast M-SEARCH, then read the friendly name from the device's own description XML.

    The reply's LOCATION is only followed when it points back at the ip that answered, so a
    device cannot make this tool fetch an arbitrary URL.
    """
    found = {}
    for ip, data in _ask({ip: SEARCH for ip in ips}, port, wait).items():
        location = urlparse(parse_ssdp(data).get("location", ""))
        if location.scheme != "http" or location.hostname != ip:
            continue
        try:
            description = parse_upnp_description(fetch(location.geturl()))
        except (OSError, ValueError):
            continue
        name = description.get("friendlyName") or description.get("modelName")
        if name:
            found[ip] = name
    return found


def discover(ips, wait, ports=None, fetch=_http_get, nmap=None, nmap_exclude=()) -> dict[str, dict[str, str]]:
    """Run the UDP probes side by side, then `nmap` (e.g. probe_nmap) on the ips none of them named
    and that are not in nmap_exclude. Returns {ip: {source: name}} for devices that answered."""
    ports = {**DEFAULT_PORTS, **(ports or {})}
    probes = {
        "mDNS": lambda: probe_mdns(ips, wait, ports["mdns"]),
        "Bonjour": lambda: probe_bonjour(ips, wait, ports["mdns"]),
        "SSDP": lambda: probe_ssdp(ips, wait, ports["ssdp"], fetch),
        "NetBIOS": lambda: probe_netbios(ips, wait, ports["netbios"]),
    }
    results: dict[str, dict[str, str]] = {}
    threads = []
    for source, run in probes.items():
        def work(source=source, run=run):
            for ip, name in run().items():
                results.setdefault(ip, {})[source] = name
        threads.append(threading.Thread(target=work))
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    if nmap:
        rest = [ip for ip in ips if ip not in results and ip not in nmap_exclude]
        for ip, name in (nmap(rest) if rest else {}).items():
            results.setdefault(ip, {})["nmap"] = name
    return results


# Service types that carry a device-level name, most personal first.
BONJOUR_SERVICES = ("_companion-link._tcp.local", "_airplay._tcp.local", "_googlecast._tcp.local",
                    "_hap._tcp.local", "_device-info._tcp.local", "_workstation._tcp.local", "_smb._tcp.local")


def instance_name(target: str) -> str | None:
    """"Aswin's iPhone" from "Aswin's iPhone._companion-link._tcp.local"; None for anything else."""
    label, sep, _rest = target.partition("._")
    return label if sep and label and not label.startswith("_") else None


def _service_rank(target: str) -> int:
    return next((i for i, service in enumerate(BONJOUR_SERVICES) if target.lower().endswith("." + service)),
                len(BONJOUR_SERVICES))


def probe_bonjour(ips, wait, port=DEFAULT_PORTS["mdns"], group="224.0.0.251") -> dict[str, str]:
    """Multicast a query per service type; devices answer with an instance name such as their own
    device name. Replies are matched to the ips we were asked about and everything else is ignored."""
    wanted = set(ips)
    best: dict[str, tuple[int, str]] = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        for service in BONJOUR_SERVICES:
            try:
                sock.sendto(build_ptr_query(service), (group, port))
            except OSError:
                continue
        deadline = time.monotonic() + wait
        while (left := deadline - time.monotonic()) > 0:
            sock.settimeout(left)
            try:
                data, addr = sock.recvfrom(4096)
            except TimeoutError:
                break
            except ConnectionResetError:
                continue
            except OSError:
                break
            if addr[0] not in wanted:
                continue
            for target in parse_ptr_targets(data):
                name = instance_name(target)
                if name and (addr[0] not in best or _service_rank(target) < best[addr[0]][0]):
                    best[addr[0]] = (_service_rank(target), name)
    return {ip: name for ip, (_rank, name) in best.items()}


# nmap, for appliances that answer none of the above: the name in their TLS certificate or web page.
# A connect scan of a few web ports needs no root; OS detection was tried and named nothing.
NMAP_PORTS = "80,443,8080,8443"
NMAP_HOST_SECONDS = 60
GENERIC_TITLES = {"web service", "login", "index", "home", "welcome", "untitled", "302 found",
                  "301 moved permanently", "404 not found", "401 unauthorized", "403 forbidden"}


def nmap_command(ips) -> list[str]:
    return ["nmap", "-sT", "-Pn", "-sV", "--version-light", "-p", NMAP_PORTS,
            "--script", "ssl-cert,http-title", "--host-timeout", f"{NMAP_HOST_SECONDS}s", "-oX", "-", *ips]


def _cert_name(script, ip: str) -> str | None:
    cn = next((e.text for e in script.iter("elem") if e.get("key") == "commonName" and e.text), None)
    # an Android TV's certificate is named by a random number, which is no name at all
    if not cn or cn.strip().lower() in ("localhost", ip) or not any(c.isalpha() for c in cn):
        return None
    try:
        ipaddress.ip_address(cn.strip())
        return None
    except ValueError:
        return cn.strip()


def _title_name(script) -> str | None:
    title = (script.get("output") or "").strip()
    if not title or title.startswith("Site doesn't have a title") or title.lower() in GENERIC_TITLES:
        return None
    return title


def parse_nmap_xml(xml: str) -> dict[str, str]:
    """{ip: name} from `nmap -oX` output: a certificate's commonName, else a page title that says
    something. IPs, numbers, localhost and stock titles such as "WEB SERVICE" are not names."""
    found: dict[str, str] = {}
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return {}
    for host in root.iter("host"):
        ip = next((a.get("addr") for a in host.iter("address") if a.get("addrtype") == "ipv4"), None)
        if not ip:
            continue
        scripts = list(host.iter("script"))
        name = (next((n for s in scripts if s.get("id") == "ssl-cert" and (n := _cert_name(s, ip))), None)
                or next((n for s in scripts if s.get("id") == "http-title" and (n := _title_name(s))), None))
        if name:
            found[ip] = name
    return found


def nmap_options(cfg) -> dict:
    """discover() keywords for a full discovery run: nmap unless NMAP_ENABLED is off."""
    return {"nmap": probe_nmap if cfg.nmap_enabled else None, "nmap_exclude": cfg.nmap_exclude}


def probe_nmap(ips, run=subprocess.run) -> dict[str, str]:
    """nmap the ips; {} if nmap is not installed, fails or runs past its time."""
    if not ips:
        return {}
    try:
        done = run(nmap_command(ips), capture_output=True, text=True,
                   timeout=NMAP_HOST_SECONDS * len(ips) + 30)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_nmap_xml(done.stdout) if done.returncode == 0 else {}
