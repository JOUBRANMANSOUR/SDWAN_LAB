"""Validated shared topology model for the isolated v4 implementation."""
from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_interface, ip_network
from pathlib import Path
from typing import Any, Mapping

from .marks import MarkLayout


class ConfigurationError(ValueError):
    pass


@dataclass(frozen=True)
class Underlay:
    name: str
    switch: str
    dpid: int
    network: IPv4Network
    overlay_network: IPv4Network
    wireguard_interface: str
    listen_port: int
    route_table: int
    mark: int
    bandwidth_mbps: float
    delay_ms: float
    loss_pct: float
    jitter_ms: float
    cost: float


@dataclass(frozen=True)
class Hub:
    name: str
    address_id: int
    management_ip: IPv4Address


@dataclass(frozen=True)
class Spoke:
    name: str
    address_id: int
    management_ip: IPv4Address
    home_hub: str
    lan_network: IPv4Network
    lan_gateway: IPv4Address
    lan_switch: str
    lan_dpid: int

    def host_ip(self, number: int) -> IPv4Address:
        if number not in (1, 2, 3):
            raise ValueError("host number must be 1, 2 or 3")
        return IPv4Address(int(self.lan_network.network_address) + 10 + number)


@dataclass(frozen=True)
class ControllerConfig:
    openflow_host: str
    openflow_port: int
    policy_port: int
    edge_port: int
    management_address: str
    shared_token_env: str


@dataclass(frozen=True)
class Settings:
    persistent_keepalive_s: int
    route_mark_mask: int
    terminal_mark_bit: int
    provisional_mark_bit: int
    emergency_mark_bit: int
    nfqueue_start: int
    nfqueue_end: int
    nfqueue_maxlen: int
    nfqueue_socket_buffer: int
    rp_filter: int
    probe_interval_s: float
    probe_count: int
    classifier_fail_mode: str
    classifier_tcp_packet_budget: int
    classifier_udp_packet_budget: int
    classifier_inspection_timeout_s: int
    classifier_tcp_handshake_timeout_s: int
    classifier_tcp_established_timeout_s: int
    classifier_tcp_closing_timeout_s: int
    classifier_udp_idle_timeout_s: int
    classifier_dns_idle_timeout_s: int
    classifier_metadata_timeout_s: int
    classifier_max_lifetime_s: int
    classifier_max_flows: int
    classifier_overload_circuit_s: int
    application_cache_ttl_s: int
    application_cache_max_entries: int
    local_blackout_failures: int
    drain_timeout_s: int

    @property
    def mark_layout(self) -> MarkLayout:
        return MarkLayout(
            self.route_mark_mask, self.terminal_mark_bit,
            self.provisional_mark_bit, self.emergency_mark_bit,
        )


@dataclass(frozen=True)
class TopologyConfig:
    source: Path
    edge_image: str
    host_image: str
    controller: ControllerConfig
    management_network: IPv4Network
    settings: Settings
    underlays: Mapping[str, Underlay]
    hubs: Mapping[str, Hub]
    spokes: Mapping[str, Spoke]

    @property
    def site_names(self) -> tuple[str, ...]:
        return tuple(self.hubs) + tuple(self.spokes)

    def site_address_id(self, site: str) -> int:
        item = self.hubs.get(site) or self.spokes.get(site)
        if item is None:
            raise KeyError(site)
        return item.address_id

    def management_ip(self, site: str) -> IPv4Address:
        item = self.hubs.get(site) or self.spokes.get(site)
        if item is None:
            raise KeyError(site)
        return item.management_ip

    def underlay_ip(self, site: str, path: str) -> IPv4Address:
        network = self.underlays[path].network
        return IPv4Address(int(network.network_address) + self.site_address_id(site))

    def overlay_ip(self, site: str, path: str) -> IPv4Address:
        network = self.underlays[path].overlay_network
        return IPv4Address(int(network.network_address) + self.site_address_id(site))


def topology_from_mapping(raw: Mapping[str, Any], source: Path) -> TopologyConfig:
    required = {"schema_version", "edge_image", "host_image", "controller", "management_network",
                "settings", "underlays", "hubs", "spokes"}
    missing = required - set(raw)
    if missing:
        raise ConfigurationError(f"topology is missing: {', '.join(sorted(missing))}")
    if raw["schema_version"] != 4:
        raise ConfigurationError("topology schema_version must be 4")
    controller = ControllerConfig(**raw["controller"])
    settings = Settings(**raw["settings"])
    underlays = {
        name: Underlay(
            name, str(item["switch"]), int(item["dpid"]), ip_network(item["network"]),
            ip_network(item["overlay_network"]), str(item["wireguard_interface"]),
            int(item["listen_port"]), int(item["route_table"]), int(item["mark"]),
            float(item["bandwidth_mbps"]), float(item["delay_ms"]),
            float(item["loss_pct"]), float(item["jitter_ms"]), float(item["cost"]),
        ) for name, item in raw["underlays"].items()
    }
    hubs = {
        name: Hub(name, int(item["address_id"]), ip_address(item["management_ip"]))
        for name, item in raw["hubs"].items()
    }
    spokes = {
        name: Spoke(
            name, int(item["address_id"]), ip_address(item["management_ip"]),
            str(item["home_hub"]), ip_network(item["lan_network"]),
            ip_address(item["lan_gateway"]), str(item["lan_switch"]), int(item["lan_dpid"]),
        ) for name, item in raw["spokes"].items()
    }
    config = TopologyConfig(
        source, str(raw["edge_image"]), str(raw["host_image"]), controller,
        ip_network(raw["management_network"]), settings, underlays, hubs, spokes,
    )
    validate_topology(config)
    return config


def validate_topology(config: TopologyConfig) -> None:
    if set(config.underlays) != {"mpls", "bb", "lte"}:
        raise ConfigurationError("underlays must be exactly mpls, bb and lte")
    if set(config.hubs) != {"hub1", "hub2"} or set(config.spokes) != {f"node{i}" for i in range(1, 6)}:
        raise ConfigurationError("topology requires hub1/hub2 and node1 through node5")
    if config.settings.classifier_fail_mode not in {"open", "closed"}:
        raise ConfigurationError("classifier_fail_mode must be open or closed")
    if not (0 <= config.settings.nfqueue_start <= config.settings.nfqueue_end <= 65535):
        raise ConfigurationError("invalid NFQUEUE range")
    if config.settings.nfqueue_maxlen <= 0 or config.settings.nfqueue_socket_buffer <= 0:
        raise ConfigurationError("NFQUEUE limits must be positive")
    classifier_limits = (
        config.settings.classifier_tcp_packet_budget,
        config.settings.classifier_udp_packet_budget,
        config.settings.classifier_inspection_timeout_s,
        config.settings.classifier_tcp_handshake_timeout_s,
        config.settings.classifier_tcp_established_timeout_s,
        config.settings.classifier_tcp_closing_timeout_s,
        config.settings.classifier_udp_idle_timeout_s,
        config.settings.classifier_dns_idle_timeout_s,
        config.settings.classifier_metadata_timeout_s,
        config.settings.classifier_max_lifetime_s,
        config.settings.classifier_max_flows,
        config.settings.classifier_overload_circuit_s,
    )
    if any(value <= 0 for value in classifier_limits):
        raise ConfigurationError("classifier budgets, timeouts and bounds must be positive")
    if (
        config.settings.application_cache_ttl_s <= 0
        or config.settings.application_cache_max_entries <= 0
        or config.settings.local_blackout_failures <= 0
        or config.settings.drain_timeout_s <= 0
    ):
        raise ConfigurationError("cache and local failover bounds must be positive")
    controller_ports = (
        config.controller.openflow_port, config.controller.policy_port,
        config.controller.edge_port,
    )
    if any(port <= 0 or port > 65535 for port in controller_ports):
        raise ConfigurationError("controller ports must be valid TCP ports")
    path_marks = {name: item.mark for name, item in config.underlays.items()}
    try:
        config.settings.mark_layout.validate(path_marks)
    except ValueError as exc:
        raise ConfigurationError(str(exc)) from exc
    dpids = [item.dpid for item in config.underlays.values()] + [item.lan_dpid for item in config.spokes.values()]
    if len(dpids) != len(set(dpids)) or any(value <= 0 or value >= 2**64 for value in dpids):
        raise ConfigurationError("OpenFlow DPIDs must be unique nonzero 64-bit values")
    ports = [item.listen_port for item in config.underlays.values()]
    tables = [item.route_table for item in config.underlays.values()]
    if len(ports) != len(set(ports)) or len(tables) != len(set(tables)):
        raise ConfigurationError("WireGuard ports and routing tables must be unique")
    if any(item.cost < 0 or item.bandwidth_mbps <= 0 for item in config.underlays.values()):
        raise ConfigurationError("underlay cost must be nonnegative and capacity must be positive")
    networks = [config.management_network]
    networks += [item.network for item in config.underlays.values()]
    networks += [item.overlay_network for item in config.underlays.values()]
    networks += [item.lan_network for item in config.spokes.values()]
    for index, left in enumerate(networks):
        for right in networks[index + 1:]:
            if left.overlaps(right):
                raise ConfigurationError(f"address spaces overlap: {left} and {right}")
    if ip_interface(config.controller.management_address).ip not in config.management_network:
        raise ConfigurationError("controller management address is outside the management network")
    ids: set[int] = set()
    addresses: set[IPv4Address] = set()
    for site in config.site_names:
        if config.site_address_id(site) in ids or config.management_ip(site) in addresses:
            raise ConfigurationError("site address IDs and management addresses must be unique")
        ids.add(config.site_address_id(site))
        addresses.add(config.management_ip(site))
    for spoke in config.spokes.values():
        if spoke.home_hub not in config.hubs or spoke.lan_gateway not in spoke.lan_network:
            raise ConfigurationError(f"invalid hub or LAN gateway for {spoke.name}")
        if spoke.lan_gateway != IPv4Address(int(spoke.lan_network.network_address) + 1):
            raise ConfigurationError(f"{spoke.name} gateway must be the first usable address")
