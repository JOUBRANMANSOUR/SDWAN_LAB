# Research and implementation evidence

This document separates published evidence from engineering decisions. None of the sources below is claimed to implement this exact Containernet/WireGuard architecture.

## Peer-reviewed foundations

- Deri et al., *nDPI: Open-Source High-Speed Deep Packet Inspection*, IWCMC 2014, [DOI 10.1109/IWCMC.2014.6906427](https://doi.org/10.1109/IWCMC.2014.6906427). Supports flow-oriented classification, per-flow state, accuracy/performance care, and embedding nDPI in a traffic application. It does not document the 2025 nDPI 5.0 API and therefore is not used as API authority.
- Gaolei Li et al., *Deep Packet Inspection Based Application-Aware Traffic Control for Software Defined Networks*, GLOBECOM 2016, [DOI 10.1109/GLOCOM.2016.7841721](https://doi.org/10.1109/GLOCOM.2016.7841721). Supports passing classification information into SDN traffic control. v4's separation of local DPI facts from controller policy is an engineering adaptation, not a claim that this paper used NFQUEUE/WireGuard.
- Guanglei Li et al., *Application-aware and Dynamic Security Function Chaining for Mobile Networks*, JISIS 2017, [DOI 10.22667/JISIS.2017.11.30.021](https://doi.org/10.22667/JISIS.2017.11.30.021). Supports classify-once flow metadata reused for subsequent packets and separation of classification from steering. v4 applies that as terminal connmark bypass and per-flow affinity.
- Trajkovska et al., *SDN-based Service Function Chaining Mechanism and Service Prototype Implementation in NFV Scenario*, 2017, [DOI 10.1016/j.csi.2017.01.002](https://doi.org/10.1016/j.csi.2017.01.002). Demonstrates the relevance of a virtualized nDPI classifier and NFV steering. A separate inline DPI VNF is not selected because this lab can isolate the native classifier process inside the edge without adding another forwarding hop/bottleneck.
- Cheng et al., OFDPI, *Journal of Network and Computer Applications* 2021, [DOI 10.1016/j.jnca.2021.103186](https://doi.org/10.1016/j.jnca.2021.103186). Supports separating DPI work from the Ryu event loop and notifying control logic with results. Mirroring/plaintext inspection concepts are transferable only before encryption; v4's underlay switches see WireGuard ciphertext and cannot perform application DPI.
- Peuster et al., *Containernet 2.0: A Rapid Prototyping Platform for Hybrid Service Function Chains*, NetSoft 2018. Supports Docker VNFs/multi-homing and controlled bandwidth/delay/loss/jitter for reproducible experiments. It does not prove production performance.
- Yuniarto et al., *Performance Analysis of Multipath Deployment in Software Defined Wide Area Networking*, 2021. Supports comparing paths using throughput/delay/loss in an SDN/Mininet-style experiment. v4's three-underlay comparison and static/v3/v4 measurement plan are the applicable methodology.

## Preprints (lower evidential weight)

- Quang et al., *Routing and QoS Policy Optimization in SD-WAN*, [arXiv:2209.12515](https://arxiv.org/abs/2209.12515). Informs application requirements, SLA/cost/capacity policy and central-versus-edge tradeoffs. It does not validate v4's implementation.
- Quang et al., *Global QoS Policy Optimization in SD-WAN*, [arXiv:2304.05473](https://arxiv.org/abs/2304.05473). A preprint supporting dynamic adaptation under cross-traffic/available-bandwidth constraints. v4 uses conservative EWMA/passive estimates and explicitly does not claim exact available bandwidth or global optimality.
- Shen et al., *WirePlanner*, [arXiv:2311.15099](https://arxiv.org/abs/2311.15099). A preprint supporting separation of route computation from WireGuard tunnel configuration and latency/cost-aware planning. v4 keeps three stable tunnel identities and limits endpoint changes to hub/WAN/recovery events.

## Official current implementation authorities

- [nDPI releases](https://github.com/ntop/nDPI/releases) identify 5.0 as the current stable release used here. The `5.0` tag was verified on 2026-07-22 as commit `375f99ef9fb4999d778b57bbeece171b3fa9fba6`.
- The pinned official `ndpi_api.h`, `ndpi_typedefs.h`, and `reader_util.c` were checked for `ndpi_init_detection_module`, `ndpi_finalize_initialization`, `ndpi_detection_process_packet`, explicit `NDPI_STATE_*`, `ndpi_detection_giveup`, protocol stacks, `ndpi_flow_malloc`, and `ndpi_flow_free`. v4 rejects `ndpi_extra_dissection_possible()` and exports native confidence/FPC labels rather than probabilities.
- [libnetfilter_queue documentation](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/) distinguishes queue-bypass/no-listener behavior from `NFQA_CFG_F_FAIL_OPEN` queue-overflow behavior. v4 configures and tests them as separate mechanisms.
- [PF_RING FT](https://www.ntop.org/guides/pf_ring/ft.html) provides managed flow tracking and nDPI integration. It is not selected: manual bounded tables are adequate for this small lab, packet marking still needs custom integration, and deployment/licensing/complexity would reduce the experiment's clarity. Profiling can reopen this decision.
- [nDPId](https://github.com/utoni/nDPId) is a useful daemon/export architecture for monitoring. It is not the inline marker because passive/event timing cannot guarantee a pre-routing mark for the first packets. It remains an optional comparison exporter only after version/maintenance compatibility is verified.

## SDN references and engineering synthesis

Nadeau and Gray's *SDN: Software Defined Networks*, Goransson/Black/Culver's *Software Defined Networks: A Comprehensive Approach*, and compatible OpenFlow 1.3 guidance support control/data-plane separation, bounded controller responsibilities, virtualization, and consistent updates. Older controller examples are not copied where they conflict with Ryu/OpenFlow 1.3.

The following are project-specific engineering decisions synthesized from the evidence:

- native C NFQUEUE for pre-route marks at laboratory traffic rates;
- local classification plus centrally authored class rankings rather than per-flow controller blocking;
- first-packet provisional release and established-flow pinning;
- source-spoke flow ownership plus ingress-WireGuard return affinity;
- route-slot remapping only for blackouts;
- separate Ryu and policy-service processes;
- no separate DPI VNF, PF_RING FT, or nDPId inline dependency by default;
- conservative hostname-required application evidence and explicit IPv6-fragment limitation;
- no claim of TLS/QUIC decryption, complete QoS allocation, production scale, or exact passive available bandwidth.
