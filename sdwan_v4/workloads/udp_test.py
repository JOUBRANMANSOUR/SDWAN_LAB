#!/usr/bin/env python3
"""Pure UDP request/response generator with no iperf3 TCP control flow."""
from __future__ import annotations

import argparse
import json
import socket
import time


def serve(bind: str, port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server:
        server.bind((bind, port))
        while True:
            payload, address = server.recvfrom(65535)
            server.sendto(payload, address)
            print(json.dumps({"peer": address, "bytes": len(payload)}), flush=True)


def client(host: str, port: int, count: int, interval: float, flow_id: str) -> None:
    results: list[float] = []
    lost = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
        connection.settimeout(1)
        connection.connect((host, port))
        local = connection.getsockname()
        for sequence in range(count):
            payload = f"{flow_id}|{sequence}|{time.time_ns()}".encode()
            started = time.monotonic()
            connection.send(payload)
            try:
                reply = connection.recv(65535)
                if reply == payload:
                    results.append((time.monotonic() - started) * 1000)
                else:
                    lost += 1
            except TimeoutError:
                lost += 1
            time.sleep(interval)
    print(json.dumps({
        "flow_id": flow_id, "transport": "UDP", "local": local,
        "remote": [host, port], "sent_datagrams": count, "lost": lost,
        "rtt_ms": results,
    }))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--bind", default="0.0.0.0")
    server.add_argument("--port", type=int, default=9999)
    sender = sub.add_parser("client")
    sender.add_argument("host")
    sender.add_argument("--port", type=int, default=9999)
    sender.add_argument("--count", type=int, default=10)
    sender.add_argument("--interval", type=float, default=0.05)
    sender.add_argument("--flow-id", default=f"udp-{int(time.time())}")
    args = parser.parse_args()
    if args.mode == "server":
        serve(args.bind, args.port)
    else:
        client(args.host, args.port, args.count, args.interval, args.flow_id)


if __name__ == "__main__":
    main()


