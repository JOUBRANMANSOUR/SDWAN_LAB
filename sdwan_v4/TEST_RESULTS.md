# Test results

## Windows checks executed on 2026-07-22

Environment: Windows host, temporary Python 3.14 validation virtual environment outside `sdwan_v4`.

| Check | Result |
|---|---|
| `python -m compileall -q sdwan_v4` | Passed |
| `python -m sdwan_v4.common.config_loader` | Passed: 7 routers, 8 OpenFlow switches, 5 application classes |
| `pytest -q -p no:cacheprovider sdwan_v4/tests -m 'not live'` | Passed: 18 passed, 1 live test deselected |
| `ruff check sdwan_v4` | Passed: all checks passed |
| executable LF/shebang audit | Passed: 12 scripts, zero CRLF files, zero missing shebangs |
| v3 aggregate preservation hash | Passed: 64 files, manifest SHA-256 `AB381147C345504121D1B6ECE933F5DB585394C496AD4345F42D781F40010E50` |
| official nDPI tag lookup | Passed: tag `5.0` -> `375f99ef9fb4999d778b57bbeece171b3fa9fba6` |
| pinned nDPI 5.0 API source review | Passed: explicit state/stack/process/give-up/allocation/free APIs verified; one incorrect free-function name was found and corrected |
| classifier nDPI symbol audit against pinned `ndpi_api.h` | Passed: all 12 referenced nDPI functions are declared by the pinned header |

These results do not prove native compilation or packet behavior.

## Ubuntu tests not run on this Windows host

This Windows host has no Docker CLI and no registered WSL distribution, so it cannot execute the Linux-native or privileged gates below.

- native C build/link against pinned nDPI and libnetfilter_queue;
- Docker edge/host builds;
- privileged Containernet topology and all eight OVS connections;
- WireGuard interfaces, peers, handshakes, and overlay forwarding;
- policy rules, iptables chains, conntrack marks, and NFQUEUE listener/overflow behavior;
- real protocol classification/pcap matrix and malformed/truncated/fragment cases;
- first-flow provisional mark, terminal transition, established pinning, and later new-flow selection;
- Nginx 1/2/3/10-flow experiment and path hysteresis;
- brownout, blackout, hub, classifier, edge, Ryu, policy-service, no-listener, queue-full, ENOBUFS, and recovery tests;
- static routing versus v3 versus v4 throughput/delay/CPU/memory/drop/loss/classification/controller-rate measurements.

Do not mark any item above as passed until its command, timestamp, configuration, raw logs, captures, and measured values are recorded. The implementation is a research candidate—not production-ready—until those gates pass.

## Ubuntu evidence locations

Store each run under an immutable timestamped directory, for example `evidence/v4-YYYYMMDDTHHMMSSZ/`, containing configuration copies, image digests, test logs, `collect_evidence.sh` output, tcpdump pcaps, CPU/memory data, traffic results, failure timeline, and v3/static/v4 comparison tables. Do not invent or prefill performance numbers.
