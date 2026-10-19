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
