"""Packet builders/parsers for the `names` probes. Packets are hand-built here, byte by byte."""

import struct

from pihole_detector.discovery import (
    build_nbstat_query, build_ptr_query, parse_nbstat, parse_ptr_targets, parse_ssdp,
    parse_upnp_description, reverse_name,
)


def enc(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"


def dns_response(answers):
    """answers: [(owner_bytes, rtype, rdata_bytes)] -> a DNS response packet."""
    body = b"".join(owner + struct.pack(">HHIH", rtype, 1, 120, len(rdata)) + rdata
                    for owner, rtype, rdata in answers)
    return struct.pack(">HHHHHH", 0, 0x8400, 0, len(answers), 0, 0) + body


def test_reverse_name_reverses_the_octets():
    assert reverse_name("192.168.18.23") == "23.18.168.192.in-addr.arpa"


def test_ptr_query_asks_for_the_name_and_requests_a_unicast_reply():
    packet = build_ptr_query("23.18.168.192.in-addr.arpa")
    _id, _flags, qd, *_ = struct.unpack(">HHHHHH", packet[:12])
    assert qd == 1
    assert packet[12:12 + len(enc("23.18.168.192.in-addr.arpa"))] == enc("23.18.168.192.in-addr.arpa")
    qtype, qclass = struct.unpack(">HH", packet[-4:])
    assert qtype == 12 and qclass == 0x8001  # PTR, IN with the unicast-response bit


def test_ptr_targets_are_read_from_the_answers():
    packet = dns_response([(enc("23.18.168.192.in-addr.arpa"), 12, enc("Aswins-iPad.local"))])
    assert parse_ptr_targets(packet) == ["Aswins-iPad.local"]


def test_ptr_targets_follow_compression_pointers():
    owner = enc("23.18.168.192.in-addr.arpa")
    # The second answer's owner is a pointer back to the first (offset 12); its target is
    # "tv" + a pointer to ".local" inside the first target.
    first_target = enc("ipad.local")
    packet = dns_response([(owner, 12, first_target)])
    local_offset = packet.index(b"\x05local")
    second = struct.pack(">H", 0xC000 | 12) + struct.pack(">HHIH", 12, 1, 120, 5) + b"\x02tv" + struct.pack(">H", 0xC000 | local_offset)
    packet = packet[:6] + struct.pack(">H", 2) + packet[8:] + second
    assert parse_ptr_targets(packet) == ["ipad.local", "tv.local"]


def test_ptr_targets_ignore_garbage():
    assert parse_ptr_targets(b"\x00\x01") == []
    assert parse_ptr_targets(b"") == []


def test_ssdp_headers_are_lowercased_keys():
    reply = b"HTTP/1.1 200 OK\r\nLOCATION: http://192.0.2.5:8080/desc.xml\r\nServer: Linux UPnP/1.0\r\n\r\n"
    assert parse_ssdp(reply) == {"location": "http://192.0.2.5:8080/desc.xml", "server": "Linux UPnP/1.0"}


def test_upnp_description_gives_friendly_name_and_model():
    xml = ('<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>'
           "<friendlyName>BRAVIA 4K</friendlyName><manufacturer>Sony</manufacturer>"
           "<modelName>KD-55X80J</modelName></device></root>")
    assert parse_upnp_description(xml) == {"friendlyName": "BRAVIA 4K", "manufacturer": "Sony",
                                           "modelName": "KD-55X80J"}


def test_upnp_description_survives_bad_xml():
    assert parse_upnp_description("<root><device>") == {}


def nbstat_response(names):
    """names: [(name, suffix, flags)] -> an NBSTAT response packet."""
    entries = b"".join(n.ljust(15).encode() + bytes([suffix]) + struct.pack(">H", flags) for n, suffix, flags in names)
    rdata = bytes([len(names)]) + entries + b"\x00" * 6
    answer = b"\x20CK" + b"A" * 30 + b"\x00" + struct.pack(">HHIH", 0x21, 1, 0, len(rdata)) + rdata
    return struct.pack(">HHHHHH", 0x1234, 0x8400, 0, 1, 0, 0) + answer


def test_nbstat_query_is_the_standard_wildcard_status_request():
    packet = build_nbstat_query()
    assert len(packet) == 50
    assert packet[12:46] == b"\x20CK" + b"A" * 30 + b"\x00"
    assert struct.unpack(">HH", packet[46:]) == (0x21, 1)


def test_nbstat_picks_the_unique_workstation_name_not_the_workgroup():
    packet = nbstat_response([("WORKGROUP", 0x00, 0x8400), ("DESKTOP-AB", 0x00, 0x0400), ("DESKTOP-AB", 0x20, 0x0400)])
    assert parse_nbstat(packet) == "DESKTOP-AB"


def test_nbstat_with_no_workstation_name_is_none():
    assert parse_nbstat(nbstat_response([("WORKGROUP", 0x00, 0x8400)])) is None
    assert parse_nbstat(b"junk") is None


# --- probes against local responders (loopback; the real ports are injected) -------------------

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from pihole_detector.discovery import discover, probe_mdns, probe_netbios, probe_ssdp

LO = "127.0.0.1"


def udp_responder(reply):
    """A one-shot UDP server on loopback. reply(request) -> bytes or None. Returns its port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LO, 0))

    def serve():
        sock.settimeout(3)
        try:
            data, addr = sock.recvfrom(2048)
            answer = reply(data)
            if answer:
                sock.sendto(answer, addr)
        except OSError:
            pass
        finally:
            sock.close()

    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def http_server(body: bytes):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer((LO, 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def test_mdns_probe_returns_the_hostname_without_dot_local():
    port = udp_responder(lambda _req: dns_response([(enc(reverse_name(LO)), 12, enc("Aswins-iPad.local"))]))
    assert probe_mdns([LO], wait=1, port=port) == {LO: "Aswins-iPad"}


def test_netbios_probe_returns_the_machine_name():
    port = udp_responder(lambda _req: nbstat_response([("WORKGROUP", 0x00, 0x8400), ("DESKTOP-AB", 0x00, 0x0400)]))
    assert probe_netbios([LO], wait=1, port=port) == {LO: "DESKTOP-AB"}


def test_probes_return_nothing_when_nobody_answers():
    port = udp_responder(lambda _req: None)
    assert probe_mdns([LO], wait=0.4, port=port) == {}


def test_ssdp_probe_fetches_the_description_and_returns_the_friendly_name():
    server = http_server(b"<root><device><friendlyName>BRAVIA 4K</friendlyName></device></root>")
    location = f"http://{LO}:{server.server_port}/desc.xml"
    port = udp_responder(lambda _req: f"HTTP/1.1 200 OK\r\nLOCATION: {location}\r\n\r\n".encode())
    assert probe_ssdp([LO], wait=1, port=port) == {LO: "BRAVIA 4K"}
    server.shutdown()


def test_ssdp_probe_never_fetches_a_location_on_another_host():
    fetched = []
    port = udp_responder(lambda _req: b"HTTP/1.1 200 OK\r\nLOCATION: http://203.0.113.9/desc.xml\r\n\r\n")
    assert probe_ssdp([LO], wait=1, port=port, fetch=lambda url: fetched.append(url) or "") == {}
    assert fetched == []


def test_discover_groups_answers_by_ip_and_source():
    mdns_port = udp_responder(lambda _req: dns_response([(enc(reverse_name(LO)), 12, enc("pc.local"))]))
    nb_port = udp_responder(lambda _req: nbstat_response([("PC-NAME", 0x00, 0x0400)]))
    ssdp_port = udp_responder(lambda _req: None)
    found = discover([LO], wait=1, ports={"mdns": mdns_port, "netbios": nb_port, "ssdp": ssdp_port})
    assert found == {LO: {"mDNS": "pc", "NetBIOS": "PC-NAME"}}


# --- Bonjour browse: multicast service queries, names read from the instance labels -------------

from pihole_detector.discovery import instance_name, probe_bonjour


def test_instance_name_is_the_label_before_the_service_type():
    assert instance_name("Aswin's iPhone._companion-link._tcp.local") == "Aswin's iPhone"
    assert instance_name("_services._dns-sd._udp.local") is None
    assert instance_name("Aswins-iPad.local") is None


def test_bonjour_probe_reads_the_device_name_from_the_service_instance():
    port = udp_responder(lambda _req: dns_response(
        [(enc("_companion-link._tcp.local"), 12, enc("Aswin's iPhone._companion-link._tcp.local"))]))
    assert probe_bonjour([LO], wait=1, port=port, group=LO) == {LO: "Aswin's iPhone"}


def test_bonjour_probe_ignores_replies_from_devices_we_did_not_ask_about():
    port = udp_responder(lambda _req: dns_response(
        [(enc("_airplay._tcp.local"), 12, enc("Stranger._airplay._tcp.local"))]))
    assert probe_bonjour(["192.0.2.1"], wait=0.5, port=port, group=LO) == {}


def test_bonjour_prefers_the_more_personal_service():
    # A companion-link instance (the device's own name) beats a generic one from the same device.
    answers = [(enc("_smb._tcp.local"), 12, enc("FILES._smb._tcp.local")),
               (enc("_companion-link._tcp.local"), 12, enc("Aswin's iPad._companion-link._tcp.local"))]
    port = udp_responder(lambda _req: dns_response(answers))
    assert probe_bonjour([LO], wait=1, port=port, group=LO) == {LO: "Aswin's iPad"}


# --- nmap: TLS certificate and page title, for devices the UDP probes could not name -------------

import subprocess

from pihole_detector.discovery import nmap_command, parse_nmap_xml, probe_nmap


def nmap_xml(*hosts):
    """hosts: (ip, [(script id, output, {elem key: value})]) -> nmap -oX output."""
    body = ""
    for ip, scripts in hosts:
        ports = "".join(
            f'<port protocol="tcp" portid="{443 + i}"><state state="open"/>'
            f'<script id="{sid}" output="{out}">'
            + "".join(f'<table key="subject"><elem key="{k}">{v}</elem></table>' for k, v in elems.items())
            + "</script></port>"
            for i, (sid, out, elems) in enumerate(scripts))
        body += f'<host><status state="up"/><address addr="{ip}" addrtype="ipv4"/><ports>{ports}</ports></host>'
    return f'<?xml version="1.0"?><nmaprun>{body}</nmaprun>'


DECO = ("192.168.18.136", [
    ("http-title", "Site doesn't have a title (text/html).", {}),
    ("ssl-cert", "Subject: commonName=tplinkdeco.net", {"commonName": "tplinkdeco.net"}),
])


def test_nmap_names_a_device_by_its_certificate():
    assert parse_nmap_xml(nmap_xml(DECO)) == {"192.168.18.136": "tplinkdeco.net"}


def test_nmap_skips_a_certificate_named_after_an_ip_localhost_or_a_number():
    # live 2026-10-27: the Sony (Android) TV's certificate is "-4574329061925171433"
    for cn in ("192.168.18.50", "localhost", "-4574329061925171433"):
        host = ("192.168.18.50", [("ssl-cert", f"Subject: commonName={cn}", {"commonName": cn}),
                                  ("http-title", "Brother HL-L2350DW", {})])
        assert parse_nmap_xml(nmap_xml(host)) == {"192.168.18.50": "Brother HL-L2350DW"}


def test_nmap_ignores_missing_and_generic_titles():
    host = ("192.168.18.139", [("http-title", "WEB SERVICE", {}),
                               ("http-title", "Site doesn't have a title (text/html).", {})])
    assert parse_nmap_xml(nmap_xml(host)) == {}


def test_nmap_xml_garbage_gives_nothing():
    assert parse_nmap_xml("not xml <") == {}


def test_nmap_command_never_needs_root():
    argv = nmap_command(["192.168.18.136"])
    assert argv[0] == "nmap" and "-sT" in argv and argv[-1] == "192.168.18.136"
    assert not {"-O", "-sS", "-sU", "-A"} & set(argv)


def test_nmap_probe_survives_nmap_missing_timing_out_or_failing():
    def missing(*a, **k):
        raise FileNotFoundError("nmap")

    def slow(*a, **k):
        raise subprocess.TimeoutExpired("nmap", 1)

    def failed(argv, **k):
        return subprocess.CompletedProcess(argv, 1, stdout=nmap_xml(DECO), stderr="")

    for run in (missing, slow, failed):
        assert probe_nmap(["192.168.18.136"], run=run) == {}


def test_nmap_probe_skips_the_run_when_there_is_nothing_to_scan():
    def run(*a, **k):
        raise AssertionError("nmap must not run")

    assert probe_nmap([], run=run) == {}


def test_discover_sends_nmap_only_the_unanswered_and_not_excluded_ips():
    mdns_port = udp_responder(lambda _req: dns_response([(enc(reverse_name(LO)), 12, enc("pc.local"))]))
    ports = {"mdns": mdns_port, "netbios": udp_responder(lambda _req: None),
             "ssdp": udp_responder(lambda _req: None)}
    asked = []

    def nmap(ips):
        asked.extend(ips)
        return {ip: "tplinkdeco.net" for ip in ips}

    found = discover([LO, "127.0.0.2", "127.0.0.3"], wait=1, ports=ports, nmap=nmap,
                     nmap_exclude=("127.0.0.3",))
    assert asked == ["127.0.0.2"]
    assert found == {LO: {"mDNS": "pc"}, "127.0.0.2": {"nmap": "tplinkdeco.net"}}
