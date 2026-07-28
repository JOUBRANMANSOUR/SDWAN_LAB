# SD-WAN v4 research implementation

`sdwan_v4` is an isolated successor to `sdwan_v3`; it does not replace or edit the root, v2, or v3 implementations. It combines a native C `libnetfilter_queue` + nDPI 5.0 inline classifier with local flow marking and a separate central class-policy service.

The design goal is a defensible Containernet experiment, not a production-readiness claim. Windows checks cover source, Python, configuration, and policy logic. Native compilation, privileged NFQUEUE, WireGuard, OVS, failure, overload, and performance evidence must be produced on Ubuntu 24.04.

## Components

- `classifier/`: native per-queue flow owners, nDPI 5.0, bounded flow tables, immutable UDS policy snapshots, and bounded asynchronous events.
- `edge_agent_v4.py`: WireGuard/routing/iptables reconciliation, classifier supervision, measurements, safe evidence cache, and blackout route-slot remapping.
- `policy_service_v4.py`: SLA/cost/capacity ranking, policy versions/TTL, overrides, and transactional hub reconciliation.
- `controller_v4.py`: OpenFlow 1.3 learning forwarding, datapath state, and port statistics only.
- `topology_v4.py`: seven routers, eight OpenFlow datapaths, three underlays, host containers, live verification, and lab CLI.
- `workloads/`: real Nginx, TLS, SSH, FTP, DNS and aioquic services plus explicit generic/negative traffic.

## Safety boundary

Do not copy `.git`, `.agents`, `.codex`, caches, virtual environments, build directories, or temporary captures. Copy the complete clean `sdwan_v4/` directory. Do not replace v3 until every Ubuntu gate in `MIGRATION.md` passes.

See `UBUNTU_RUNBOOK.md` for exact environments and startup order, `ARCHITECTURE.md` for packet semantics, and `TEST_RESULTS.md` for executed versus pending evidence.
