"""Pure WireGuard and policy-route desired-state generation for v4 Phase 1."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from ipaddress import ip_network
from typing import Mapping

from .common.model import TopologyConfig


@dataclass(frozen=True)
class PeerState:
    site: str
    public_key: str
    allowed_ips: tuple[str, ...]
    endpoint: str | None
    keepalive_s: int


@dataclass(frozen=True)
class InterfaceState:
    name: str
    address: str
    listen_port: int
    route_table: int
    route_slot: int
    peers: tuple[PeerState, ...]
    routes: tuple[str, ...]


@dataclass(frozen=True)
class RouterDesiredState:
    schema_version: int
    site: str
    active_hub: str | None
    version: int
    interfaces: tuple[InterfaceState, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def initial_assignments(config: TopologyConfig) -> dict[str, str]:
    return {name: spoke.home_hub for name, spoke in config.spokes.items()}


def validate_assignments(config: TopologyConfig, assignments: Mapping[str, str]) -> None:
    if set(assignments) != set(config.spokes):
        raise ValueError("hub assignments must contain every spoke exactly once")
    if any(hub not in config.hubs for hub in assignments.values()):
        raise ValueError("hub assignment references an unknown hub")


def _peer(
    config: TopologyConfig, keys: Mapping[str, str], path: str, site: str,
    allowed: list[str], endpoint: bool,
) -> PeerState:
    underlay = config.underlays[path]
    return PeerState(
        site=site,
        public_key=keys[site],
        allowed_ips=tuple(sorted(set(allowed))),
        endpoint=(f"{config.underlay_ip(site, path)}:{underlay.listen_port}" if endpoint else None),
        keepalive_s=(config.settings.persistent_keepalive_s if endpoint else 0),
    )


def build_desired_states(
    config: TopologyConfig, public_keys: Mapping[str, str],
    assignments: Mapping[str, str] | None = None, version: int = 1,
) -> dict[str, RouterDesiredState]:
    """Build complete idempotent state; an Edge rejects versions older than its current state.

    Phase 1 keeps one interface per transport and one active hub per spoke.  The data
    model deliberately identifies peers and interfaces independently so Phase 2 can
    introduce one interface per (hub, transport) without changing controller APIs.
    """
    assignments = dict(assignments or initial_assignments(config))
    validate_assignments(config, assignments)
    missing = set(config.site_names) - set(public_keys)
    if missing:
        raise ValueError(f"missing public keys: {sorted(missing)}")
    lans = {site: str(value.lan_network) for site, value in config.spokes.items()}
    states: dict[str, RouterDesiredState] = {}
    for site in config.site_names:
        interfaces: list[InterfaceState] = []
        active_hub: str | None = assignments.get(site)
        for path, underlay in config.underlays.items():
            peers: list[PeerState] = []
            if site in config.spokes:
                hub = assignments[site]
                allowed = [f"{config.overlay_ip(hub, path)}/32"]
                allowed.extend(network for spoke, network in lans.items() if spoke != site)
                peers.append(_peer(config, public_keys, path, hub, allowed, True))
                routes = tuple(sorted(network for spoke, network in lans.items() if spoke != site))
            else:
                other_hub = next(name for name in config.hubs if name != site)
                remote = [spoke for spoke, hub in assignments.items() if hub == other_hub]
                local = [spoke for spoke, hub in assignments.items() if hub == site]
                interhub = [f"{config.overlay_ip(other_hub, path)}/32"] + [lans[name] for name in remote]
                peers.append(_peer(config, public_keys, path, other_hub, interhub, True))
                for spoke in sorted(local):
                    peers.append(_peer(
                        config, public_keys, path, spoke,
                        [f"{config.overlay_ip(spoke, path)}/32", lans[spoke]], True,
                    ))
                routes = tuple(sorted(lans.values()))
            interfaces.append(InterfaceState(
                underlay.wireguard_interface,
                f"{config.overlay_ip(site, path)}/{underlay.overlay_network.prefixlen}",
                underlay.listen_port, underlay.route_table, underlay.mark,
                tuple(peers), routes,
            ))
        states[site] = RouterDesiredState(4, site, active_hub, version, tuple(interfaces))
    validate_allowed_ips(states)
    return states


def validate_allowed_ips(states: Mapping[str, RouterDesiredState]) -> None:
    for state in states.values():
        for interface in state.interfaces:
            owners: list[tuple[object, str]] = []
            for peer in interface.peers:
                for prefix in peer.allowed_ips:
                    network = ip_network(prefix)
                    for previous_network, previous_site in owners:
                        if previous_site != peer.site and network.overlaps(previous_network):  # type: ignore[union-attr]
                            raise ValueError(
                                f"{state.site}/{interface.name}: {network} overlaps "
                                f"{previous_network} on peers {previous_site}/{peer.site}"
                            )
                    owners.append((network, peer.site))

