#!/usr/bin/env python3
"""Small deterministic TCP flow generator; this is generic TCP, not HTTP."""
from __future__ import annotations

import argparse
import json
import socket
import time


def serve(bind: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((bind, port))
        server.listen(16)
        while True:
            connection, address = server.accept()
            with connection:
                payload = connection.recv(65535)
                connection.sendall(payload)
                print(json.dumps({"peer": address, "bytes": len(payload)}), flush=True)


def client(host: str, port: int, size: int, flow_id: str) -> None:
    payload = (flow_id.encode() + b"|") * max(1, size // (len(flow_id) + 1))
    payload = payload[:size]
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=5) as connection:
        local = connection.getsockname()
        connection.sendall(payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = connection.recv(65535)
            if not chunk:
                break
            received.extend(chunk)
    print(json.dumps({
        "flow_id": flow_id, "transport": "TCP", "local": local,
        "remote": [host, port], "sent_bytes": len(payload),
        "received_bytes": len(received), "duration_s": time.monotonic() - started,
        "verified": bytes(received) == payload,
    }))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--bind", default="0.0.0.0")
    server.add_argument("--port", type=int, default=9000)
    sender = sub.add_parser("client")
    sender.add_argument("host")
    sender.add_argument("--port", type=int, default=9000)
    sender.add_argument("--bytes", type=int, default=32768)
    sender.add_argument("--flow-id", default=f"tcp-{int(time.time())}")
    args = parser.parse_args()
    if args.mode == "server":
        serve(args.bind, args.port)
    else:
        client(args.host, args.port, args.bytes, args.flow_id)


if __name__ == "__main__":
    main()

