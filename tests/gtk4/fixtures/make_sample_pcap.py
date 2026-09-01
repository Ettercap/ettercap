#!/usr/bin/env python3
"""
Generate tests/gtk4/fixtures/sample.pcap.

The GTK4 harness needs a pcap with known contents so the list-view checks can
assert on a specific number of rows and specific host addresses. Generating it
from a script rather than checking in a capture keeps the fixture reviewable
and reproducible -- and avoids committing a binary blob whose provenance
nobody can verify.

The traffic is synthetic: two hosts exchanging a short HTTP request and
response, which is enough for ettercap to populate the host list, the
connection list and the HTTP dissector.

Usage:  python3 tests/gtk4/fixtures/make_sample_pcap.py
"""

from __future__ import annotations

import struct
from pathlib import Path

OUT = Path(__file__).parent / "sample.pcap"

CLIENT_MAC = bytes.fromhex("020000000001")
SERVER_MAC = bytes.fromhex("020000000002")
CLIENT_IP = (10, 0, 0, 1)
SERVER_IP = (10, 0, 0, 2)
CLIENT_PORT = 51000
SERVER_PORT = 80


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4(src, dst, payload: bytes, proto: int = 6) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack(
        "!BBHHHBBH4B4B",
        0x45, 0, total_len, 0, 0x4000, 64, proto, 0,
        *src, *dst,
    )
    hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport, dport, seq, ack, flags, payload: bytes, src, dst) -> bytes:
    hdr = struct.pack(
        "!HHIIBBHHH", sport, dport, seq, ack, 0x50, flags, 8192, 0, 0
    )
    pseudo = struct.pack("!4B4BBBH", *src, *dst, 0, 6, len(hdr) + len(payload))
    hdr = hdr[:16] + struct.pack(
        "!H", checksum(pseudo + hdr + payload)
    ) + hdr[18:]
    return hdr + payload


def ether(src_mac, dst_mac, payload: bytes) -> bytes:
    return dst_mac + src_mac + struct.pack("!H", 0x0800) + payload


def c2s(seq, ack, flags, payload=b"") -> bytes:
    return ether(
        CLIENT_MAC, SERVER_MAC,
        ipv4(CLIENT_IP, SERVER_IP,
             tcp(CLIENT_PORT, SERVER_PORT, seq, ack, flags, payload,
                 CLIENT_IP, SERVER_IP)),
    )


def s2c(seq, ack, flags, payload=b"") -> bytes:
    return ether(
        SERVER_MAC, CLIENT_MAC,
        ipv4(SERVER_IP, CLIENT_IP,
             tcp(SERVER_PORT, CLIENT_PORT, seq, ack, flags, payload,
                 SERVER_IP, CLIENT_IP)),
    )


SYN, SYN_ACK, ACK, PSH_ACK, FIN_ACK = 0x02, 0x12, 0x10, 0x18, 0x11

REQUEST = (
    b"GET /index.html HTTP/1.1\r\n"
    b"Host: example.invalid\r\n"
    b"User-Agent: ettercap-gtk4-fixture/1.0\r\n"
    b"\r\n"
)
RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/plain\r\n"
    b"Content-Length: 12\r\n"
    b"\r\n"
    b"hello world\n"
)

PACKETS = [
    c2s(1000, 0, SYN),
    s2c(2000, 1001, SYN_ACK),
    c2s(1001, 2001, ACK),
    c2s(1001, 2001, PSH_ACK, REQUEST),
    s2c(2001, 1001 + len(REQUEST), PSH_ACK, RESPONSE),
    c2s(1001 + len(REQUEST), 2001 + len(RESPONSE), FIN_ACK),
    s2c(2001 + len(RESPONSE), 1002 + len(REQUEST), FIN_ACK),
]


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("wb") as fh:
        # magic, version 2.4, no tz correction, no sigfigs, snaplen, Ethernet
        fh.write(struct.pack("!IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, pkt in enumerate(PACKETS):
            fh.write(struct.pack("!IIII", 1700000000 + i, 0, len(pkt), len(pkt)))
            fh.write(pkt)
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes, {len(PACKETS)} packets)")


if __name__ == "__main__":
    main()
