# Architecture

## Packet and control paths

```text
LAN packet
  -> mangle/PREROUTING SDWAN_V4_OUT
  -> CONNMARK restore
  -> emergency route-slot handling
  -> terminal-bit bypass
  -> explicit UNKNOWN provisional mark
  -> CONNMARK save
  -> NFQUEUE 42..45 (flow-affine worker)
  -> native nDPI state and metadata
  -> application/category -> SLA class
  -> current ranked-path snapshot
  -> active low-byte mark
  -> CONNMARK save
  -> ip rule -> table 101/102/103
  -> wg-mpls / wg-bb / wg-lte
```

```text
edge RTT/loss/jitter/utilization/queue/WireGuard measurements
          + Ryu encrypted-underlay datapath/port state
  -> policy_service_v4
  -> versioned, expiring, ranked paths per site and SLA class
  -> edge UDS snapshot
  -> atomic classifier policy replacement
```

No packet callback performs REST, DNS lookup, YAML parsing, file I/O, or blocking logging. Classification events go to a bounded asynchronous Unix-datagram queue. OpenFlow switches see encrypted WireGuard UDP, so they provide forwarding/state/counters—not application classification.

## Mark ABI

| Bits | Meaning |
|---|---|
| `0x0ff` | Route slot: `1=mpls`, `2=bb`, `3=lte` |
| `0x100` | Inspection is terminal; userspace separately records classified versus terminal-unknown |
| `0x200` | Inspection is provisional/incomplete |
| `0x400` | Emergency route-slot remapping applies |

Examples: `0x202` is provisional Broadband; `0x102` is terminal on the Broadband route slot. `0x100` is never described as classification accuracy.

## First and later packets

1. A new LAN-originated flow gets the configured UNKNOWN-class path before NFQUEUE. This release policy is explicit; it does not depend on the main routing table.
2. If nDPI classifies the first packet, the native policy layer may select the application class's current first-ranked path.
3. Otherwise the packet is released immediately on the provisional path. TCP handshakes are not held for DPI or a controller round trip.
4. nDPI continues only while its state is `INSPECTING`, `PARTIAL`, or locally bounded metadata work remains. Unique TCP payload evidence, not ACKs/retransmissions, consumes the local budget.
5. nDPI `CLASSIFIED` becomes userspace `CLASSIFIED`; an exhausted/give-up unknown becomes `TERMINAL_UNKNOWN`; a budget-ended provisional identification becomes `TERMINAL_PARTIAL`; nDPI `MONITORING` is exported as `OPTIONAL_METADATA_MONITORING` even though inline processing is deliberately truncated and the kernel terminal bit is set.
6. If classification completes after the first packet, `desired_path` is recorded but `active_path` stays pinned. TCP and UDP are not generally migrated. The result informs telemetry, application evidence, and future policy analysis.
7. Later packets restore the conntrack mark. Terminal flows bypass userspace.

This means v4 does not promise perfect first-packet application steering. DNS and some signatures may classify immediately; TLS/QUIC and ambiguous traffic often cannot.

## Flow ownership and direction

The spoke where a connection first enters from its LAN owns the bidirectional nDPI flow. Canonical IPv4/IPv6 address/port ordering associates both directions with one record, while the first TCP SYN determines client direction; a first-seen SYN/ACK reverses that assumption.

At the receiving spoke, a connection with no existing connmark is not independently application-steered. Its return affinity is derived from the ingress `wg-mpls`, `wg-bb`, or `wg-lte` interface and saved to conntrack. A server-initiated LAN flow is owned by the server's spoke. Simultaneous-open TCP is treated as a laboratory edge case and must be validated before relying on its direction metadata.

## Flow bounds and evidence

Each queue has its own nDPI module and flow table; the configured global maximum is divided across workers. Initialization is serialized. Idle expiry distinguishes TCP handshake, established TCP, FIN/RST grace, UDP, and maximum lifetime. Eviction and expiry free the nDPI object once and export counters.

The evidence cache stores application/category/native-confidence/source/hostname/destination/transport/port/catalog-version/TTL/conflicts. It never stores a path. Empty-hostname, terminal-unknown, address-only, and port-hint entries cannot become authoritative, avoiding shared-CDN IP assumptions. In v4 this cache is conservative telemetry; it does not override the first-packet pinning rule.

## Fragments and IPv6

IPv4 relies on normal Linux conntrack defragmentation before mangle/PREROUTING. Noninitial fragments reaching userspace are rejected by the parser and follow configured fail behavior; ports are never invented. IPv6 base-header TCP/UDP is parsed, but IPv6 extension chains and fragments are explicitly rejected rather than misparsed. Full bounded reassembly is future work and must be tested with overlap/missing-first-fragment cases before enabling.

## Failure behavior

- No listener: iptables `--queue-bypass` is used only in fail-open mode; the packet already has a known provisional path mark.
- Queue full: `NFQA_CFG_F_FAIL_OPEN` is configured separately; `ENOBUFS`, truncation, parse, verdict, expiry, eviction, and event-drop counters are exported. ENOBUFS opens a short configurable local bypass circuit using the explicit fallback mark.
- Classifier crash: the edge restarts it with bounded exponential backoff and a restart circuit. Existing conntrack marks are retained.
- Policy-service loss: the edge uses the latest unexpired snapshot, then an explicit bootstrap ranking after expiry. Same-generation stale versions are rejected.
- Ryu loss: existing OVS flows and Linux/WireGuard steering continue; new underlay learning may be affected.
- Brownout: ranked policy changes after samples/hysteresis/hold-down; only new flows normally use the new choice.
- Blackout: the edge remaps the affected route table to a healthy transport, marks the event as emergency, drains/reconciles recovery, and avoids per-packet path selection.
- Hub change: only failover/recovery may change WireGuard endpoints; the policy service applies and verifies all three overlays with rollback. Phase 1 is not fully make-before-break.

Research demonstrations and normal enterprise-like lab traffic default fail-open for availability. A security-class-specific fail-closed action is not yet implemented; global fail-closed must be explicitly configured and tested.

## QoS scope

v4 ranks paths using configured capacity, EWMA utilization, cross-traffic counters, queue state, RTT, jitter, loss, handshake state, and cost. Passive counters are estimates, not exact available bandwidth. v4 does not implement class schedulers, bandwidth reservation, or a full QoS optimizer; optional `tc` class scheduling is future work.
