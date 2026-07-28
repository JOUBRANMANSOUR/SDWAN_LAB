# Migration from sdwan_v3

## Component migration table

| Current component | Current problem | Reusable parts | Replacement design | New v4 file |
|---|---|---|---|---|
| `classifier_v3.py` | Python NFQUEUE parsing, ctypes, GIL/global-lock serialization, nDPI 4.14 assumptions | Flow-oriented intent and classify-once goal | Native C queues with one flow owner/module per worker | `classifier/*.c` |
| v3 nDPI shim | Removed `ndpi_extra_dissection_possible()` and old return semantics | Protocol/category/hostname objectives | Pinned nDPI 5.0 state, full stack, native confidence/FPC metadata, exact cleanup | `classifier/ndpi_engine.c` |
| v3 UNKNOWN/PROVISIONAL/CONFIRMED | Packet-limit unknown was called confirmed | Fast terminal bypass bit | Distinct inspecting, partial, classified, terminal-unknown, monitoring, expired, failed | `classifier/classifier.h`, `common/marks.py` |
| fixed 32-packet rule | Same budget for every protocol and duplicate evidence | Bounded inspection | nDPI state plus separate TCP/UDP evidence/time budgets | `classifier/nfqueue_worker.c`, `config/topology.yaml` |
| local percentage confidence | Labels were converted to invented probabilities | Expose confidence | Preserve nDPI enum/name and separate FPC source | `classifier/ndpi_engine.c`, `event_export.c` |
| both-spoke steering | Independent decisions can be asymmetric | Bidirectional canonical key | LAN-origin owner; receiver derives return affinity from ingress WG | `edge_agent_v4.py`, `flow_table.c` |
| UDP final re-steering | Established UDP could move despite policy | Per-flow connmark | TCP and UDP pin by default; only blackout remaps a route slot | `nfqueue_worker.c`, `app_policy.yaml` |
| accidental first-packet route | Unknown traffic could follow main-route accidents | Provisional concept | Explicit fallback mark before queue; immediate release; no controller wait | `edge_agent_v4.py` |
| weak expiration | One idle timeout and unclear cleanup | Bounded table idea | TCP-state/UDP/lifetime expiry, bounded per-worker tables, reason counters | `flow_table.c` |
| fragment association | Incomplete reassembly can invent associations | Kernel networking position | Depend on IPv4 conntrack defrag; reject unresolved/IPv6 fragments explicitly | `packet_parser.c` |
| application cache | Useful TTL/conflict idea but unsafe path/IP coupling risk | Bounded TTL/conflicts | Evidence only, hostname required, no selected path stored | `common/application_evidence.py` |
| classifier lifecycle | Detection without strong recovery/readiness | Edge-local process placement | Readiness check, restart backoff/circuit, clean stop, mark preservation | `edge_agent_v4.py`, `main.c` |
| NFQUEUE fail-open | Queue-bypass confused with queue-full behavior | Lab fail mode | Separate queue-bypass and `NFQA_CFG_F_FAIL_OPEN`, explicit fallback, counters/circuit | `edge_agent_v4.py`, `nfqueue_worker.c` |
| blocking classification reports | Hot-path delivery could be lost or block | Classification telemetry | Bounded nonblocking UDS event exporter with drop counters | `event_export.c` |
| `controller_v3.py` | Ryu and SD-WAN policy responsibilities coupled | OF1.3 learning and DPIDs | Ryu forwarding/stats only; separate policy process | `controller_v4.py`, `policy_service_v4.py` |
| per-flow controller dependency | First-flow latency and outage dependency | Versioned policy idea | Expiring class-level ranked snapshots; local immediate execution | `policy_service_v4.py`, `policy_model.py` |
| short byte-counter capacity | Not exact available bandwidth | RTT/loss/jitter/counters | multi-sample EWMA utilization, queue/drop/retransmit/handshake/cost inputs | `metrics_v4.py`, `path_selection_v4.py` |
| WireGuard endpoints | Endpoint changes must not implement application steering | Three interfaces/tables 101-103 | Select existing route table; endpoints change only for hub/WAN/tunnel recovery | `desired_state_v4.py`, `edge_agent_v4.py` |
| v3 workload service | Minimal servers are weak for concurrency | Protocol generators | Nginx-light plus real TLS/SSH/FTP/DNS/aioquic and explicit negative UDP/443 | `docker/Dockerfile.host.v4`, `workloads/` |
| tcpdump expectations | Capture can be confused with classification | Troubleshooting value | LAN/WG/underlay evidence only; never production classification | `scripts/collect_evidence.sh` |

## Stages and gates

1. Keep v3 active and copy v4 alongside it.
2. Recompute `V3_BASELINE.md`; any mismatch stops migration.
3. Run v4 Python/config/static tests.
4. Build the edge image and compile the native classifier against the pinned nDPI commit.
5. Run topology/WireGuard/OpenFlow/routing/NFQUEUE checks.
6. Run protocol, first-flow, pinning, new-flow, brownout, blackout, process-failure, no-listener, queue-overload, controller/policy outage, hub-failure, and recovery tests.
7. Compare static routing, v3, and v4 with measured throughput, delay, CPU, memory, drops, loss, classification latency, flow scale, and controller rate.
8. Only after all evidence is recorded may entry points/configuration references be changed from v3 to v4. No file is replaced automatically.

## Final responsibility map

| v3 responsibility | Eventual v4 replacement |
|---|---|
| Python DPI/NFQUEUE/flow state | `classifier/` native binary |
| edge routing, marks, WireGuard, local monitoring | `edge_agent_v4.py` and supporting v4 modules |
| combined controller/policy behavior | `controller_v4.py` plus independent `policy_service_v4.py` |
| topology | `topology_v4.py` |
| edge/host images | `docker/Dockerfile.edge.v4`, `docker/Dockerfile.host.v4` |
| v3 configuration | validated files under `config/` |
| traffic tools | `workloads/` and Nginx configuration |
| v3 run/test documentation | v4 README, architecture, runbook, evidence, migration, and test results |

## Rollback

Stop the v4 topology and services, run `sudo mn -c`, remove only v4 containers/images if desired, and start v3 with its original commands. Do not reuse v4 conntrack marks, generated WireGuard keys, policy snapshots, or evidence as v3 state. Because v3 files remain byte-for-byte preserved, rollback does not require source restoration.
