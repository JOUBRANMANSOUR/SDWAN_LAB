#!/usr/bin/env python3
"""Concurrent HTTP transaction runner using curl timing evidence."""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import subprocess
import time
from typing import Any


FORMAT = '{"remote_ip":"%{remote_ip}","local_ip":"%{local_ip}","http_code":%{http_code},' \
         '"connect_s":%{time_connect},"ttfb_s":%{time_starttransfer},"total_s":%{time_total},' \
         '"bytes":%{size_download},"speed_Bps":%{speed_download}}'


def download(url: str, identifier: str, insecure: bool) -> dict[str, Any]:
    command = [
        "curl", "--fail", "--silent", "--show-error", "--output", "/dev/null",
        "--header", f"X-SDWAN-Flow-ID: {identifier}", "--write-out", FORMAT,
    ]
    if insecure:
        command.append("--insecure")
    command.append(url)
    started = time.time()
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode:
        return {"id": identifier, "ok": False, "error": completed.stderr.strip()}
    value = json.loads(completed.stdout)
    value.update(id=identifier, ok=True, started_at=started)
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("--clients", type=int, default=1)
    parser.add_argument("--insecure", action="store_true")
    parser.add_argument("--prefix", default=f"http-{int(time.time())}")
    args = parser.parse_args()
    if args.clients <= 0 or args.clients > 200:
        parser.error("--clients must be between 1 and 200")
    wall_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.clients) as pool:
        futures = [
            pool.submit(download, args.url, f"{args.prefix}-{number}", args.insecure)
            for number in range(1, args.clients + 1)
        ]
        results = [future.result() for future in as_completed(futures)]
    wall = time.monotonic() - wall_start
    total = sum(float(item.get("bytes", 0)) for item in results)
    print(json.dumps({
        "experiment": args.prefix, "transactions": args.clients, "wall_s": wall,
        "aggregate_mbps": total * 8 / max(wall, 0.001) / 1_000_000,
        "results": sorted(results, key=lambda item: item["id"]),
    }, indent=2))


if __name__ == "__main__":
    main()


