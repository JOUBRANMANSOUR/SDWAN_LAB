#!/usr/bin/env python3
"""Deterministic SIP, STUN-like, RTP-like, and negative UDP/443 fixtures.

The UDP/443 fixture is intentionally non-QUIC. It verifies that a port hint is
not promoted to a confirmed protocol. Real QUIC uses quic_test.py and aioquic.
"""
from __future__ import annotations

import argparse
import os
import socket
import struct
import time


def payload(kind: str, sequence: int) -> tuple[int, bytes]:
    if kind == "sip":
        return 5060, (
            "OPTIONS sip:lab@sdwan.local SIP/2.0\r\n"
            "Via: SIP/2.0/UDP client.sdwan.local:5060\r\n"
            f"Call-ID: sdwan-v4-{sequence}\r\nContent-Length: 0\r\n\r\n"
        ).encode()
    if kind == "stun":
        return 3478, struct.pack("!HHI12s", 0x0001, 0, 0x2112A442, os.urandom(12))
    if kind == "rtp":
        return 5004, struct.pack("!BBHII", 0x80, 96, sequence, sequence * 160, 0x53445741) + b"lab-audio"
    if kind == "udp443-nonquic":
        return 443, bytes([0xC3, 0, 0, 0, 1]) + os.urandom(24)
    raise ValueError(kind)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("kind", choices=("sip", "stun", "rtp", "udp443-nonquic"))
    parser.add_argument("host")
    parser.add_argument("--count", type=int, default=5)
    args = parser.parse_args()
    port, _ = payload(args.kind, 0)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        for sequence in range(args.count):
            _, data = payload(args.kind, sequence)
            connection.sendto(data, (args.host, port))
            time.sleep(0.05)
        print(f"sent {args.count} {args.kind} datagrams to {args.host}:{port}")


if __name__ == "__main__":
    main()

