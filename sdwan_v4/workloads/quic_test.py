#!/usr/bin/env python3
"""Real QUIC echo flow using Ubuntu's aioquic package."""
from __future__ import annotations

import argparse
import asyncio
import ssl
import time

from aioquic.asyncio import QuicConnectionProtocol, connect, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import QuicEvent, StreamDataReceived


ALPN = ["sdwan-v4-echo"]


class EchoProtocol(QuicConnectionProtocol):
    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, StreamDataReceived):
            self._quic.send_stream_data(event.stream_id, event.data, event.end_stream)
            self.transmit()


async def run_server(bind: str, port: int, certificate: str, private_key: str) -> None:
    configuration = QuicConfiguration(is_client=False, alpn_protocols=ALPN)
    configuration.load_cert_chain(certificate, private_key)
    await serve(bind, port, configuration=configuration, create_protocol=EchoProtocol)
    await asyncio.Future()


async def run_client(host: str, port: int, message: str) -> None:
    configuration = QuicConfiguration(is_client=True, alpn_protocols=ALPN)
    configuration.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    async with connect(host, port, configuration=configuration) as protocol:
        reader, writer = await protocol.create_stream()
        writer.write(message.encode())
        writer.write_eof()
        response = await asyncio.wait_for(reader.read(), timeout=5)
    print({
        "transport": "QUIC", "host": host, "port": port,
        "verified": response.decode() == message,
        "duration_s": time.monotonic() - started,
    })


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--bind", default="0.0.0.0")
    server.add_argument("--port", type=int, default=443)
    server.add_argument("--certificate", default="/etc/nginx/tls/lab.crt")
    server.add_argument("--private-key", default="/etc/nginx/tls/lab.key")
    client = sub.add_parser("client")
    client.add_argument("host")
    client.add_argument("--port", type=int, default=443)
    client.add_argument("--message", default="sdwan-v4-quic")
    args = parser.parse_args()
    if args.mode == "server":
        asyncio.run(run_server(args.bind, args.port, args.certificate, args.private_key))
    else:
        asyncio.run(run_client(args.host, args.port, args.message))


if __name__ == "__main__":
    main()


