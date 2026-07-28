#!/usr/bin/env python3
"""Router-local actuator, fast failover, metrics, and secured lab API."""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hmac
import json
import logging
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import threading
import time
from typing import Any, Mapping

from flask import Flask, jsonify, request
import requests

from .command_v4 import CommandError, LocalCommandRunner
from .config_loader_v4 import PolicyBundle, load_bundle
from .common.policy_model import RankedPolicySnapshot, snapshot_from_mapping
from .common.application_evidence import ApplicationEvidenceCache, EvidenceKey
from .local_failover import LocalFailoverManager
from .metrics_v4 import metric_from_ping
from .observability import configure_logging


LOG = logging.getLogger("sdwan.edge.v4")
OUT_CHAIN = "SDWAN_V4_OUT"
IN_CHAIN = "SDWAN_V4_IN"
EMERGENCY_CHAIN = "SDWAN_V4_EMERG"


class StaleVersion(ValueError):
    pass


@dataclass
class AgentState:
    site: str
    active_hub: str | None = None
    reconcile_version: int = 0
    decision_version: int = 0
    decisions: dict[str, str] = field(default_factory=dict)
    ranked_paths: dict[str, list[str]] = field(default_factory=dict)
    policy_generation: str = ""
    policy_expires_at: float = 0.0
    desired: dict[str, Any] | None = None
    recent_classifications: list[dict[str, Any]] = field(default_factory=list)
    recent_metrics: list[dict[str, Any]] = field(default_factory=list)
    classifier_stats: dict[str, Any] = field(default_factory=dict)
    local_events: list[dict[str, Any]] = field(default_factory=list)
    last_error: str | None = None
    classifier_pid: int | None = None
    classifier_alive: bool = False
    classifier_restart_attempts: int = 0
    classifier_circuit_open_until: float = 0.0
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def public(self, failover: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "site": self.site, "active_hub": self.active_hub,
            "reconcile_version": self.reconcile_version,
            "decision_version": self.decision_version,
            "decisions": dict(self.decisions), "ranked_paths": dict(self.ranked_paths),
            "policy_generation": self.policy_generation,
            "policy_expires_at": self.policy_expires_at, "last_error": self.last_error,
            "classifier_pid": self.classifier_pid, "classifier_alive": self.classifier_alive,
            "classifier_restart_attempts": self.classifier_restart_attempts,
            "classifier_circuit_open_until": self.classifier_circuit_open_until,
            "recent_classifications": self.recent_classifications[-100:],
            "recent_metrics": self.recent_metrics[-30:], "local_events": self.local_events[-30:],
            "classifier_stats": dict(self.classifier_stats),
            "local_failover": dict(failover), "updated_at": self.updated_at,
        }


class NetworkActuator:
    def __init__(self, site: str, bundle: PolicyBundle, private_key: Path):
        self.site = site
        self.bundle = bundle
        self.config = bundle.topology
        self.private_key = private_key
        self.runner = LocalCommandRunner(site)
        self.current: dict[str, Any] | None = None
        self.route_version = 0
        self.emergency_slots: set[str] = set()
        self._lock = threading.RLock()

    def run(self, argv: list[str], operation: str, accepted: set[int] = {0}) -> str:
        return self.runner.run(argv, operation, accepted=accepted).stdout

    def configure_baseline(self) -> None:
        settings = self.config.settings
        self.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], "enable IPv4 forwarding")
        self.run(["sysctl", "-w", f"net.ipv4.conf.all.rp_filter={settings.rp_filter}"], "set rp_filter")
        for path, underlay in self.config.underlays.items():
            self._replace_rule(
                1000 + underlay.mark,
                ["fwmark", f"{underlay.mark}/{settings.route_mark_mask}", "lookup", str(underlay.route_table)],
            )
            if self.site in self.config.hubs:
                self._replace_rule(
                    1100 + underlay.mark,
                    ["iif", underlay.wireguard_interface, "lookup", str(underlay.route_table)],
                )
            LOG.info("policy_rule_ready", extra={"site": self.site, "path": path})
        if self.site in self.config.spokes:
            self._configure_classifier_chains()

    def _replace_rule(self, priority: int, rule: list[str]) -> None:
        while self.runner.run(
            ["ip", "rule", "del", "priority", str(priority)], "remove stale rule",
            accepted={0, 2},
        ).returncode == 0:
            pass
        self.run(["ip", "rule", "add", "priority", str(priority), *rule], "install policy rule")

    def _ensure_hook(self, chain: str, interface: str) -> None:
        rule = ["PREROUTING", "-i", interface, "-j", chain]
        result = self.runner.run(
            ["iptables", "-t", "mangle", "-C", *rule], "check mangle hook", accepted={0, 1},
        )
        if result.returncode:
            self.run(["iptables", "-t", "mangle", "-I", *rule], "install mangle hook")

    def _configure_classifier_chains(self) -> None:
        settings = self.config.settings
        layout = settings.mark_layout
        combined = hex(layout.combined_mask)
        terminal = hex(layout.terminal_bit)
        fallback_class = str(self.bundle.applications["unknown_class"])
        fallback_path = str(self.bundle.applications["classes"][fallback_class]["preference"][0])
        fallback_mark = self.config.underlays[fallback_path].mark | layout.provisional_bit
        for chain in (OUT_CHAIN, IN_CHAIN, EMERGENCY_CHAIN):
            self.run(["iptables", "-t", "mangle", "-N", chain], f"create {chain}", {0, 1})
            self.run(["iptables", "-t", "mangle", "-F", chain], f"flush {chain}")
        self._ensure_hook(OUT_CHAIN, f"{self.site}-lan")
        for underlay in self.config.underlays.values():
            self._ensure_hook(IN_CHAIN, underlay.wireguard_interface)
        restore = [
            "-j", "CONNMARK", "--restore-mark", "--nfmask", combined, "--ctmask", combined,
        ]
        save = ["-j", "CONNMARK", "--save-mark", "--nfmask", combined, "--ctmask", combined]
        self.run(["iptables", "-t", "mangle", "-A", OUT_CHAIN, *restore], "restore outbound mark")
        self.run([
            "iptables", "-t", "mangle", "-A", OUT_CHAIN, "-j", EMERGENCY_CHAIN,
        ], "attach emergency marker subchain")
        self.run([
            "iptables", "-t", "mangle", "-A", OUT_CHAIN, "-m", "mark", "--mark",
            f"{terminal}/{terminal}", "-j", "RETURN",
        ], "bypass outbound terminal flow")
        self.run([
            "iptables", "-t", "mangle", "-A", OUT_CHAIN, "-m", "mark", "--mark",
            f"0x0/{hex(layout.path_mask)}", "-j", "MARK", "--set-xmark",
            f"{hex(fallback_mark)}/{combined}",
        ], "assign explicit provisional fallback")
        self.run(["iptables", "-t", "mangle", "-A", OUT_CHAIN, *save], "save fallback mark")
        out_queue = [
            "iptables", "-t", "mangle", "-A", OUT_CHAIN, "-j", "NFQUEUE",
            "--queue-balance", f"{settings.nfqueue_start}:{settings.nfqueue_end}",
        ]
        if settings.classifier_fail_mode == "open":
            out_queue.append("--queue-bypass")
        self.run(out_queue, "attach outbound NFQUEUE")
        self.run(["iptables", "-t", "mangle", "-A", OUT_CHAIN, *save], "save outbound mark")

        self.run(["iptables", "-t", "mangle", "-A", IN_CHAIN, *restore], "restore inbound mark")
        # Terminal return traffic is delivered to LAN with its skb mark cleared,
        # while the conntrack mark remains available for the reverse packet.
        self.run([
            "iptables", "-t", "mangle", "-A", IN_CHAIN, "-m", "connmark", "--mark",
            f"{terminal}/{terminal}", "-j", "MARK", "--set-xmark", f"0x0/{combined}",
        ], "clear LAN-bound mark for terminal return packet")
        self.run([
            "iptables", "-t", "mangle", "-A", IN_CHAIN, "-m", "connmark", "--mark",
            f"{terminal}/{terminal}", "-j", "RETURN",
        ], "bypass inbound terminal flow")
        # A non-zero provisional connmark means this is the return direction of
        # a LAN-originated flow. It goes to the same balanced queue range so
        # nDPI receives bidirectional evidence.
        in_queue = [
            "iptables", "-t", "mangle", "-A", IN_CHAIN, "-m", "connmark", "!",
            "--mark", f"0x0/{hex(layout.path_mask)}", "-j", "NFQUEUE",
            "--queue-balance", f"{settings.nfqueue_start}:{settings.nfqueue_end}",
        ]
        if settings.classifier_fail_mode == "open":
            in_queue.append("--queue-bypass")
        self.run(in_queue, "attach inbound NFQUEUE")
        self.run(["iptables", "-t", "mangle", "-A", IN_CHAIN, *save], "save inbound connmark")
        # A new connection first seen on WireGuard is owned by the remote spoke.
        # Pin its return traffic to the ingress transport without a second DPI
        # policy decision at this receiving spoke.
        for underlay in self.config.underlays.values():
            ingress_mark = underlay.mark | layout.terminal_bit
            self.run([
                "iptables", "-t", "mangle", "-A", IN_CHAIN, "-i",
                underlay.wireguard_interface, "-m", "connmark", "--mark",
                f"0x0/{hex(layout.path_mask)}", "-j", "MARK", "--set-xmark",
                f"{hex(ingress_mark)}/{combined}",
            ], f"derive return affinity from {underlay.wireguard_interface}")
            self.run([
                "iptables", "-t", "mangle", "-A", IN_CHAIN, "-i",
                underlay.wireguard_interface, "-m", "mark", "--mark",
                f"{hex(ingress_mark)}/{combined}", *save,
            ], f"save return affinity for {underlay.wireguard_interface}")
        self.run([
            "iptables", "-t", "mangle", "-A", IN_CHAIN, "-j", "MARK",
            "--set-xmark", f"0x0/{combined}",
        ], "clear LAN-bound packet mark")

    def reconcile(self, desired: Mapping[str, Any]) -> None:
        with self._lock:
            version = int(desired["version"])
            if desired.get("schema_version") != 4 or desired.get("site") != self.site:
                raise ValueError("desired-state schema or site mismatch")
            if self.current and version <= int(self.current["version"]):
                raise StaleVersion(f"reconcile version {version} is not newer")
            previous = self.current
            try:
                self._apply(desired)
                self.current = dict(desired)
            except Exception:
                if previous:
                    self._apply(previous)
                    self.current = previous
                raise

    def _apply(self, desired: Mapping[str, Any]) -> None:
        if not self.private_key.is_file():
            raise FileNotFoundError("WireGuard private key is missing")
        main_routes: set[str] = set()
        default_interface: str | None = None
        for interface in desired["interfaces"]:
            name = str(interface["name"])
            default_interface = default_interface or name
            exists = self.runner.run(["ip", "link", "show", "dev", name], "check WG link", {0, 1})
            if exists.returncode:
                self.run(["ip", "link", "add", "dev", name, "type", "wireguard"], "create WG link")
            self.run(["ip", "address", "replace", str(interface["address"]), "dev", name], "address WG link")
            self.run([
                "wg", "set", name, "private-key", str(self.private_key),
                "listen-port", str(interface["listen_port"]),
            ], "configure WG private key")
            current = set(self.run(["wg", "show", name, "peers"], "read WG peers").split())
            wanted = {str(peer["public_key"]) for peer in interface["peers"]}
            for key in current - wanted:
                self.run(["wg", "set", name, "peer", key, "remove"], "remove stale WG peer")
            for peer in interface["peers"]:
                command = [
                    "wg", "set", name, "peer", str(peer["public_key"]),
                    "allowed-ips", ",".join(peer["allowed_ips"]),
                    "persistent-keepalive", str(peer.get("keepalive_s", 0)),
                ]
                if peer.get("endpoint"):
                    command.extend(["endpoint", str(peer["endpoint"])])
                self.run(command, f"reconcile WG peer {peer['site']}")
            self.run(["ip", "link", "set", "dev", name, "up"], "bring WG link up")
            table = str(interface["route_table"])
            self.run(["ip", "route", "flush", "table", table], f"flush route table {table}")
            for prefix in interface["routes"]:
                main_routes.add(str(prefix))
                self.run(["ip", "route", "replace", str(prefix), "dev", name, "table", table], "install slot route")
        if default_interface:
            for prefix in main_routes:
                self.run(["ip", "route", "replace", prefix, "dev", default_interface], "install main fallback route")
        self.route_version += 1

    def remap_slot(self, slot: str, physical_path: str, expected_version: int) -> int:
        """Transactionally point one existing mark/table slot at another tunnel."""
        with self._lock:
            if expected_version != self.route_version:
                raise StaleVersion("route-slot version changed before emergency transaction")
            if not self.current:
                raise RuntimeError("cannot remap before desired state is installed")
            interfaces = {item["name"]: item for item in self.current["interfaces"]}
            failed = self.config.underlays[slot]
            backup = self.config.underlays[physical_path]
            routes = interfaces[failed.wireguard_interface]["routes"]
            applied: list[str] = []
            previous_emergency = set(self.emergency_slots)
            try:
                for prefix in routes:
                    self.run([
                        "ip", "route", "replace", str(prefix), "dev", backup.wireguard_interface,
                        "table", str(failed.route_table),
                    ], f"emergency remap {slot} to {physical_path}")
                    applied.append(str(prefix))
                if slot == physical_path:
                    self.emergency_slots.discard(slot)
                else:
                    self.emergency_slots.add(slot)
                self._render_emergency_markers()
            except CommandError:
                self.emergency_slots = previous_emergency
                marker_rollback_error: CommandError | None = None
                try:
                    self._render_emergency_markers()
                except CommandError as exc:
                    marker_rollback_error = exc
                for prefix in applied:
                    self.run([
                        "ip", "route", "replace", prefix, "dev", failed.wireguard_interface,
                        "table", str(failed.route_table),
                    ], "rollback emergency route")
                if marker_rollback_error is not None:
                    raise RuntimeError(
                        f"emergency marker rollback failed: {marker_rollback_error}"
                    ) from marker_rollback_error
                raise
            self.route_version += 1
            return self.route_version

    def _render_emergency_markers(self) -> None:
        layout = self.config.settings.mark_layout
        self.run(
            ["iptables", "-t", "mangle", "-F", EMERGENCY_CHAIN],
            "reset emergency marker rules",
        )
        for slot in sorted(self.emergency_slots):
            mark = self.config.underlays[slot].mark
            self.run([
                "iptables", "-t", "mangle", "-A", EMERGENCY_CHAIN,
                "-m", "mark", "--mark", f"{hex(mark)}/{hex(layout.path_mask)}",
                "-j", "MARK", "--or-mark", hex(layout.emergency_bit),
            ], f"mark emergency slot {slot}")
            self.run([
                "iptables", "-t", "mangle", "-A", EMERGENCY_CHAIN,
                "-m", "mark", "--mark", f"{hex(mark)}/{hex(layout.path_mask)}",
                "-j", "CONNMARK", "--save-mark", "--nfmask", hex(layout.combined_mask),
                "--ctmask", hex(layout.combined_mask),
            ], f"persist emergency slot {slot}")

    def active_flows_by_slot(self) -> dict[str, int]:
        output = self.runner.run(["conntrack", "-L", "-o", "extended"], "read conntrack", {0, 1}).stdout
        result = {name: 0 for name in self.config.underlays}
        marks = {underlay.mark: name for name, underlay in self.config.underlays.items()}
        mask = self.config.settings.route_mark_mask
        for line in output.splitlines():
            for token in line.split():
                if token.startswith("mark="):
                    try:
                        name = marks.get(int(token.split("=", 1)[1], 0) & mask)
                    except ValueError:
                        name = None
                    if name:
                        result[name] += 1
        return result

    def qdisc_stats(self, interface: str) -> tuple[int, int]:
        output = self.runner.run(
            ["tc", "-s", "qdisc", "show", "dev", interface], "read qdisc statistics", {0, 1},
        ).stdout
        dropped = re.search(r"dropped\s+(\d+)", output)
        backlog = re.search(r"backlog\s+(\d+)b", output)
        return int(dropped.group(1)) if dropped else 0, int(backlog.group(1)) if backlog else 0

    def tcp_retransmissions(self) -> int:
        output = self.runner.run(
            ["nstat", "-az", "TcpRetransSegs"], "read TCP retransmissions", {0, 1},
        ).stdout
        for line in output.splitlines():
            fields = line.split()
            if fields and fields[0] == "TcpRetransSegs" and len(fields) > 1:
                try:
                    return int(fields[1])
                except ValueError:
                    return 0
        return 0

    @staticmethod
    def nfqueue_stats() -> list[dict[str, int]]:
        try:
            lines = Path("/proc/net/netfilter/nfnetlink_queue").read_text().splitlines()
        except OSError:
            return []
        result: list[dict[str, int]] = []
        for line in lines:
            fields = line.split()
            if len(fields) < 8:
                continue
            try:
                result.append({
                    "queue": int(fields[0]), "peer_portid": int(fields[1]),
                    "queued": int(fields[2]), "copy_mode": int(fields[3]),
                    "copy_range": int(fields[4]), "kernel_dropped": int(fields[5]),
                    "userspace_dropped": int(fields[6]), "id_sequence": int(fields[7]),
                })
            except ValueError:
                continue
        return result

    def cleanup(self) -> None:
        if self.site not in self.config.spokes:
            return
        hooks = [(OUT_CHAIN, f"{self.site}-lan")]
        hooks.extend((IN_CHAIN, item.wireguard_interface) for item in self.config.underlays.values())
        for chain, interface in hooks:
            self.runner.run([
                "iptables", "-t", "mangle", "-D", "PREROUTING", "-i", interface,
                "-j", chain,
            ], "detach v4 classifier hook", {0, 1})
        for chain in (OUT_CHAIN, IN_CHAIN):
            self.runner.run(["iptables", "-t", "mangle", "-F", chain], "flush v4 chain", {0, 1})
            self.runner.run(["iptables", "-t", "mangle", "-X", chain], "delete v4 chain", {0, 1})
        self.runner.run(
            ["iptables", "-t", "mangle", "-F", EMERGENCY_CHAIN],
            "flush v4 emergency chain", {0, 1},
        )
        self.runner.run(
            ["iptables", "-t", "mangle", "-X", EMERGENCY_CHAIN],
            "delete v4 emergency chain", {0, 1},
        )


class EdgeAgent:
    def __init__(
        self, site: str, bundle: PolicyBundle, private_key: Path,
        controller_url: str, token: str = "",
    ):
        if site not in bundle.topology.site_names:
            raise ValueError(f"unknown site: {site}")
        self.site, self.bundle = site, bundle
        self.controller_url = controller_url.rstrip("/")
        self.token = token
        defaults = {name: rule["preference"][0] for name, rule in bundle.applications["classes"].items()}
        rankings = {name: list(rule["preference"]) for name, rule in bundle.applications["classes"].items()}
        self.state = AgentState(site, decisions=defaults, ranked_paths=rankings)
        self.actuator = NetworkActuator(site, bundle, private_key)
        self.failover = LocalFailoverManager(
            tuple(bundle.topology.underlays), bundle.topology.settings.drain_timeout_s,
        )
        self.failure_counts = {path: 0 for path in bundle.topology.underlays}
        self.epoch = 0
        self.classifier: subprocess.Popen[str] | None = None
        self.classifier_policy_socket = Path("/run/sdwan/classifier-policy.sock")
        self.classifier_event_socket = Path("/run/sdwan/classifier-events.sock")
        self.event_socket: socket.socket | None = None
        self.policy_snapshot = self._default_snapshot()
        self.application_evidence = ApplicationEvidenceCache(
            bundle.topology.settings.application_cache_max_entries,
            bundle.topology.settings.application_cache_ttl_s,
        )
        self.state.decision_version = self.policy_snapshot.version
        self.state.policy_generation = self.policy_snapshot.generation
        self.state.policy_expires_at = self.policy_snapshot.expires_at
        self.classifier_restart_attempts = 0
        self.classifier_next_restart = 0.0
        self.classifier_started_at = 0.0
        self.stop_event = threading.Event()
        self.lock = threading.RLock()
        self.app = Flask(f"sdwan-v4-edge-{site}")
        self.app.config["MAX_CONTENT_LENGTH"] = 256 * 1024
        self._routes()

    def authorized(self) -> bool:
        return not self.token or hmac.compare_digest(request.headers.get("X-SDWAN-Token", ""), self.token)

    def _routes(self) -> None:
        @self.app.before_request
        def authentication() -> Any:
            if request.path != "/healthz" and not self.authorized():
                return jsonify({"error": "unauthorized"}), 401
            return None

        @self.app.get("/healthz")
        def health() -> Any:
            self._classifier_health()
            healthy = self.site not in self.bundle.topology.spokes or self.state.classifier_alive
            return jsonify({
                "site": self.site, "healthy": healthy,
                "classifier_alive": self.state.classifier_alive,
                "reconcile_version": self.state.reconcile_version,
            }), 200 if healthy else 503

        @self.app.get("/sdwan/local-policy")
        def local_policy() -> Any:
            return jsonify(self.policy_snapshot.to_dict())

        @self.app.get("/sdwan/state")
        def state() -> Any:
            return jsonify(self.public())

        @self.app.get("/sdwan/classifications")
        def classifications() -> Any:
            return jsonify(self.state.recent_classifications[-100:])

        @self.app.post("/sdwan/classification")
        def classification() -> Any:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify({"error": "JSON object required"}), 400
            with self.lock:
                self.state.recent_classifications.append(payload)
                self.state.recent_classifications = self.state.recent_classifications[-100:]
            return jsonify({"accepted": True}), 202

        @self.app.post("/sdwan/classifier-stats")
        def classifier_stats() -> Any:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify({"error": "JSON object required"}), 400
            self.state.classifier_stats.update(payload)
            return jsonify({"accepted": True}), 202

        @self.app.post("/sdwan/decision")
        def decision() -> Any:
            try:
                self.apply_decision(request.get_json(silent=True))
                return jsonify(self.public())
            except (TypeError, ValueError, StaleVersion) as exc:
                return jsonify({"error": str(exc)}), 409

        @self.app.post("/sdwan/reconcile")
        def reconcile() -> Any:
            payload = request.get_json(silent=True)
            if not isinstance(payload, dict):
                return jsonify({"error": "JSON object required"}), 400
            try:
                self.actuator.reconcile(payload)
                with self.lock:
                    self.state.desired = payload
                    self.state.active_hub = payload.get("active_hub")
                    self.state.reconcile_version = int(payload["version"])
                return jsonify(self.public())
            except (CommandError, TypeError, ValueError, RuntimeError) as exc:
                self.state.last_error = str(exc)
                return jsonify({"error": str(exc)}), 409

        @self.app.post("/sdwan/probe")
        def probe() -> Any:
            hub = str((request.get_json(silent=True) or {}).get("hub", ""))
            if hub not in self.bundle.topology.hubs:
                return jsonify({"error": "unknown hub"}), 400
            return jsonify({"metrics": self.collect_metrics((hub,))})

    def public(self) -> dict[str, Any]:
        return self.state.public(self.failover.snapshot())

    def apply_decision(self, payload: Any) -> None:
        if not isinstance(payload, dict) or payload.get("site") != self.site:
            raise ValueError("decision site mismatch")
        snapshot = snapshot_from_mapping(payload)
        valid_classes = set(self.bundle.applications["classes"])
        valid_paths = set(self.bundle.topology.underlays)
        snapshot.validate(valid_classes, valid_paths)
        if snapshot.expired():
            raise ValueError("decision is already expired")
        with self.lock:
            same_generation = snapshot.generation == self.state.policy_generation
            if same_generation and snapshot.version <= self.state.decision_version:
                raise StaleVersion("decision is stale")
            self.policy_snapshot = snapshot
            self.state.ranked_paths = {
                name: list(paths) for name, paths in snapshot.ranked_paths.items()
            }
            self.state.decisions = {name: paths[0] for name, paths in snapshot.ranked_paths.items()}
            self.state.decision_version = snapshot.version
            self.state.policy_generation = snapshot.generation
            self.state.policy_expires_at = snapshot.expires_at
            self.state.updated_at = datetime.now(timezone.utc).isoformat()
        self._send_policy_snapshot()

    def _default_snapshot(self) -> RankedPolicySnapshot:
        now = time.time()
        applications = self.bundle.applications
        return RankedPolicySnapshot(
            site=self.site, version=1, generation="edge-bootstrap", epoch=0,
            created_at=now, expires_at=now + 86400, catalog_version=1,
            ranked_paths={
                name: tuple(map(str, rule["preference"]))
                for name, rule in applications["classes"].items()
            },
            applications={str(key): str(value) for key, value in applications["applications"].items()},
            categories={str(key): str(value) for key, value in applications.get("categories", {}).items()},
            unknown_class=str(applications["unknown_class"]),
            path_marks={name: item.mark for name, item in self.bundle.topology.underlays.items()},
            fail_mode=self.bundle.topology.settings.classifier_fail_mode,
        )

    def _send_policy_snapshot(self) -> bool:
        if self.policy_snapshot.expired():
            self.state.last_error = "central policy expired; using explicit bootstrap ranking"
            self.policy_snapshot = self._default_snapshot()
            self.policy_snapshot = RankedPolicySnapshot(
                **{**self.policy_snapshot.__dict__, "generation": "edge-expired"}
            )
        payload = json.dumps(self.policy_snapshot.to_dict(), separators=(",", ":")).encode()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            client.sendto(payload, str(self.classifier_policy_socket))
            return True
        except OSError as exc:
            LOG.debug("classifier_policy_delivery_pending", extra={"error": str(exc)})
            return False
        finally:
            client.close()

    def _headers(self) -> dict[str, str]:
        return {"X-SDWAN-Token": self.token} if self.token else {}

    def start(self) -> None:
        self.actuator.configure_baseline()
        if self.site in self.bundle.topology.spokes:
            self._start_event_receiver()
            try:
                self._start_classifier()
            except RuntimeError as exc:
                self.state.last_error = str(exc)
                LOG.error("classifier_initial_start_failed", extra={"error": str(exc)})
        threading.Thread(target=self._monitor, name="edge-monitor", daemon=True).start()

    def _start_event_receiver(self) -> None:
        self.classifier_event_socket.parent.mkdir(parents=True, exist_ok=True)
        self.classifier_event_socket.unlink(missing_ok=True)
        self.event_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.event_socket.bind(str(self.classifier_event_socket))
        self.event_socket.settimeout(0.5)
        threading.Thread(target=self._event_receiver, name="classifier-events", daemon=True).start()

    def _event_receiver(self) -> None:
        while not self.stop_event.is_set() and self.event_socket is not None:
            try:
                raw = self.event_socket.recv(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError("event must be an object")
                with self.lock:
                    if payload.get("type") == "stats":
                        workers = self.state.classifier_stats.setdefault("workers", {})
                        workers[str(payload.get("queue", "unknown"))] = payload
                    else:
                        self.state.recent_classifications.append(payload)
                        self.state.recent_classifications = self.state.recent_classifications[-100:]
                        self._remember_application_evidence(payload)
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                LOG.warning("invalid_classifier_event", extra={"error": str(exc)})

    def _remember_application_evidence(self, payload: Mapping[str, Any]) -> None:
        if int(payload.get("result", -1)) not in {2, 4}:
            return
        confidence_name = str(payload.get("native_confidence_name", "")).upper()
        if "PORT" in confidence_name or "MATCH_BY_IP" in confidence_name or "UNKNOWN" in confidence_name:
            return
        try:
            key = EvidenceKey(
                str(payload["server_address"]), str(payload["transport"]),
                int(payload["server_port"]), str(payload.get("hostname", "")),
            )
            fpc_name = str(payload.get("fpc_confidence_name", "")).upper()
            source = "dns-association" if "DNS" in fpc_name else "ndpi"
            self.application_evidence.remember(
                key, application=str(payload["application"]),
                category=str(payload.get("category", "Unspecified")),
                native_confidence=int(payload.get("native_confidence", 0)),
                source=source, catalog_version=self.policy_snapshot.catalog_version,
            )
            self.state.classifier_stats["application_evidence_entries"] = len(
                self.application_evidence
            )
        except (KeyError, TypeError, ValueError):
            LOG.warning("incomplete_application_evidence_event")

    def _start_classifier(self) -> None:
        settings = self.bundle.topology.settings
        if self.classifier is not None and self.classifier.poll() is None:
            return
        self.classifier_policy_socket.parent.mkdir(parents=True, exist_ok=True)
        self.classifier_policy_socket.unlink(missing_ok=True)
        layout = settings.mark_layout
        unknown = str(self.bundle.applications["unknown_class"])
        fallback_path = str(self.bundle.applications["classes"][unknown]["preference"][0])
        fallback_mark = self.bundle.topology.underlays[fallback_path].mark | layout.provisional_bit
        command = [
            "/usr/local/sbin/sdwan-classifier-v4", "--site", self.site,
            "--queue-start", str(settings.nfqueue_start),
            "--queue-end", str(settings.nfqueue_end),
            "--queue-maxlen", str(settings.nfqueue_maxlen),
            "--socket-buffer", str(settings.nfqueue_socket_buffer),
            "--policy-socket", str(self.classifier_policy_socket),
            "--event-socket", str(self.classifier_event_socket),
            "--path-mask", str(layout.path_mask),
            "--terminal-bit", str(layout.terminal_bit),
            "--provisional-bit", str(layout.provisional_bit),
            "--emergency-bit", str(layout.emergency_bit),
            "--fallback-mark", str(fallback_mark),
            "--tcp-budget", str(settings.classifier_tcp_packet_budget),
            "--udp-budget", str(settings.classifier_udp_packet_budget),
            "--inspection-timeout", str(settings.classifier_inspection_timeout_s),
            "--max-flows", str(settings.classifier_max_flows),
            "--tcp-handshake-timeout", str(settings.classifier_tcp_handshake_timeout_s),
            "--tcp-established-timeout", str(settings.classifier_tcp_established_timeout_s),
            "--tcp-closing-timeout", str(settings.classifier_tcp_closing_timeout_s),
            "--udp-timeout", str(settings.classifier_udp_idle_timeout_s),
            "--dns-timeout", str(settings.classifier_dns_idle_timeout_s),
            "--metadata-timeout", str(settings.classifier_metadata_timeout_s),
            "--max-lifetime", str(settings.classifier_max_lifetime_s),
            "--overload-circuit", str(settings.classifier_overload_circuit_s),
            "--fail-mode", settings.classifier_fail_mode,
        ]
        self.classifier = subprocess.Popen(command, text=True)
        time.sleep(0.25)
        if self.classifier.poll() is not None:
            raise RuntimeError("classifier exited during startup")
        self.state.classifier_pid = self.classifier.pid
        self.state.classifier_alive = True
        self.classifier_started_at = time.monotonic()
        for _ in range(20):
            if self.classifier_policy_socket.exists():
                break
            if self.classifier.poll() is not None:
                raise RuntimeError("classifier exited before control socket became ready")
            time.sleep(0.05)
        if not self.classifier_policy_socket.exists():
            raise RuntimeError("classifier policy socket did not become ready")
        time.sleep(0.1)
        if self.classifier.poll() is not None:
            raise RuntimeError("classifier NFQUEUE workers did not become ready")
        self._send_policy_snapshot()

    def _classifier_health(self) -> None:
        self.state.classifier_alive = (
            self.site not in self.bundle.topology.spokes
            or (self.classifier is not None and self.classifier.poll() is None)
        )

    def _maybe_restart_classifier(self) -> None:
        if self.site not in self.bundle.topology.spokes:
            return
        self._classifier_health()
        now = time.monotonic()
        if self.state.classifier_alive:
            if now - self.classifier_started_at > 60:
                self.classifier_restart_attempts = 0
            return
        if now < self.classifier_next_restart:
            return
        if self.classifier_restart_attempts >= 8:
            self.classifier_restart_attempts = 0
            self.classifier_next_restart = now + 300
            self.state.classifier_circuit_open_until = self.classifier_next_restart
            self.state.last_error = "classifier restart circuit open for 300 seconds"
            return
        self.classifier_restart_attempts += 1
        self.state.classifier_restart_attempts = self.classifier_restart_attempts
        self.classifier_next_restart = now + min(30, 2 ** self.classifier_restart_attempts)
        try:
            self._start_classifier()
        except (OSError, RuntimeError) as exc:
            self.state.last_error = str(exc)
            LOG.error("classifier_restart_failed", extra={"attempt": self.classifier_restart_attempts, "error": str(exc)})

    def _handshake_age(self, interface: str) -> float | None:
        values: list[float] = []
        output = self.actuator.runner.run(
            ["wg", "show", interface, "latest-handshakes"], "read WG handshakes", {0, 1},
        ).stdout
        for line in output.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[1].isdigit() and int(fields[1]) > 0:
                values.append(max(0.0, time.time() - int(fields[1])))
        return min(values) if values else None

    def _rate_mbps(self, interface: str, direction: str, interval_s: float = 0.1) -> float:
        path = Path(f"/sys/class/net/{interface}/statistics/{direction}_bytes")
        try:
            first = int(path.read_text().strip())
            time.sleep(interval_s)
            second = int(path.read_text().strip())
            return max(0.0, (second - first) * 8 / interval_s / 1_000_000)
        except (OSError, ValueError):
            return 0.0

    def collect_metrics(self, hubs: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
        if self.site not in self.bundle.topology.spokes:
            return []
        self.epoch += 1
        result: list[dict[str, Any]] = []
        count = self.bundle.topology.settings.probe_count
        active_flows = self.actuator.active_flows_by_slot()
        retransmissions = self.actuator.tcp_retransmissions()
        for hub in hubs or (self.state.active_hub or self.bundle.topology.spokes[self.site].home_hub,):
            for path, underlay in self.bundle.topology.underlays.items():
                outer = self.actuator.runner.run([
                    "ping", "-n", "-I", f"{self.site}-{path}", "-c", "1", "-W", "1",
                    str(self.bundle.topology.underlay_ip(hub, path)),
                ], "underlay probe", {0, 1})
                overlay = self.actuator.runner.run([
                    "ping", "-n", "-I", underlay.wireguard_interface, "-c", str(count),
                    "-W", "1", str(self.bundle.topology.overlay_ip(hub, path)),
                ], "overlay probe", {0, 1})
                tx = self._rate_mbps(f"{self.site}-{path}", "tx")
                rx = self._rate_mbps(f"{self.site}-{path}", "rx")
                queue_drops, queue_backlog = self.actuator.qdisc_stats(f"{self.site}-{path}")
                metric = metric_from_ping(
                    epoch=self.epoch, site=self.site, hub=hub, underlay=path,
                    output=overlay.stdout + overlay.stderr, transmitted=count,
                    underlay_reachable=outer.returncode == 0,
                    overlay_reachable=overlay.returncode == 0,
                    handshake_age_s=self._handshake_age(underlay.wireguard_interface),
                    capacity_mbps=underlay.bandwidth_mbps, tx_mbps=tx, rx_mbps=rx,
                    queue_drops=queue_drops, queue_backlog_bytes=queue_backlog,
                    active_flows=active_flows.get(path, 0),
                    tcp_retransmissions=retransmissions,
                ).to_dict()
                result.append(metric)
        return result

    def _emergency_check(self, metrics: list[dict[str, Any]]) -> None:
        settings = self.bundle.topology.settings
        healthy = {
            str(item["underlay"]): bool(item["link_up"] and item["overlay_reachable"])
            for item in metrics
        }
        metric_by_path = {str(item["underlay"]): item for item in metrics}
        for path in self.bundle.topology.underlays:
            self.failure_counts[path] = 0 if healthy.get(path, False) else self.failure_counts[path] + 1
            slot = self.failover.slots[path]
            if self.failure_counts[path] >= settings.local_blackout_failures and not slot.failed:
                backups = [
                    name for name in self.bundle.topology.underlays
                    if name != path and healthy.get(name)
                ]
                backups.sort(key=lambda name: (
                    -float(metric_by_path[name].get("available_mbps", 0.0)),
                    float(metric_by_path[name].get("rtt_avg_ms") or 1e9),
                ))
                if not backups:
                    continue
                backup = backups[0]
                expected = self.actuator.route_version
                self.actuator.remap_slot(path, backup, expected)
                self.failover.blackout(path, backup)
                self._event("blackout", path, backup)
            elif healthy.get(path) and slot.failed:
                self.failover.begin_recovery(path)
                self._event("recovery-drain-start", path, slot.physical_path)
        ready = self.failover.ready_to_restore(self.actuator.active_flows_by_slot())
        for candidate in ready:
            expected = self.actuator.route_version
            self.actuator.remap_slot(candidate.slot, candidate.slot, expected)
            restored = self.failover.complete_recovery(candidate.slot)
            self._event("recovery-restored", restored.slot, restored.slot)

    def _event(self, event: str, slot: str, physical_path: str) -> None:
        payload = {
            "site": self.site, "event": event, "slot": slot,
            "physical_path": physical_path, "version": self.failover.version,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.state.local_events.append(payload)
        try:
            requests.post(
                f"{self.controller_url}/sdwan/local-event", json=payload,
                headers=self._headers(), timeout=0.5,
            ).raise_for_status()
        except requests.RequestException as exc:
            LOG.warning("local_event_report_failed", extra={"error": str(exc)})

    def _monitor(self) -> None:
        interval = self.bundle.topology.settings.probe_interval_s
        while not self.stop_event.wait(interval):
            self._maybe_restart_classifier()
            if self.state.classifier_alive:
                self._send_policy_snapshot()
            try:
                metrics = self.collect_metrics()
                self.state.recent_metrics.extend(metrics)
                self.state.recent_metrics = self.state.recent_metrics[-30:]
                self.state.classifier_stats["kernel_queues"] = self.actuator.nfqueue_stats()
                self._emergency_check(metrics)
                for metric in metrics:
                    requests.post(
                        f"{self.controller_url}/sdwan/metrics", json=metric,
                        headers=self._headers(), timeout=0.6,
                    ).raise_for_status()
            except (CommandError, requests.RequestException, RuntimeError, ValueError) as exc:
                self.state.last_error = str(exc)
                LOG.error("edge_monitor_error", extra={"site": self.site, "error": str(exc)})

    def stop(self) -> None:
        self.stop_event.set()
        if self.classifier and self.classifier.poll() is None:
            self.classifier.terminate()
            try:
                self.classifier.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.classifier.kill()
        if self.event_socket is not None:
            self.event_socket.close()
        self.classifier_event_socket.unlink(missing_ok=True)
        self.classifier_policy_socket.unlink(missing_ok=True)
        self.actuator.cleanup()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--site", required=True)
    parser.add_argument("--config-dir", type=Path, required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--controller-url", required=True)
    parser.add_argument("--bind", default="")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()
    configure_logging()
    bundle = load_bundle(args.config_dir)
    token = os.getenv(bundle.topology.controller.shared_token_env, "")
    agent = EdgeAgent(args.site, bundle, args.private_key, args.controller_url, token)
    stop_requested = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop_requested.set())
    signal.signal(signal.SIGTERM, lambda *_: stop_requested.set())
    from werkzeug.serving import make_server
    agent.start()
    bind_address = args.bind or str(bundle.topology.management_ip(args.site))
    server = make_server(bind_address, args.port, agent.app, threaded=True)
    server.timeout = 0.5
    try:
        while not stop_requested.is_set():
            server.handle_request()
    finally:
        server.server_close()
        agent.stop()


if __name__ == "__main__":
    main()
