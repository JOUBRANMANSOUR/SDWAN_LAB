"""YAML loading and cross-file validation for v4."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import yaml

from .model import ConfigurationError, TopologyConfig, topology_from_mapping


CONFIG_DIR = Path(__file__).resolve().parent.parent / "config"


@dataclass(frozen=True)
class PolicyBundle:
    topology: TopologyConfig
    sla: Mapping[str, Any]
    applications: Mapping[str, Any]
    workloads: Mapping[str, Any]


def _read_yaml(path: Path) -> Mapping[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ConfigurationError(f"cannot load {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ConfigurationError(f"{path} must contain a YAML mapping")
    return value


def load_bundle(config_dir: Path | str = CONFIG_DIR) -> PolicyBundle:
    directory = Path(config_dir).resolve()
    topology = topology_from_mapping(_read_yaml(directory / "topology.yaml"), directory / "topology.yaml")
    sla = _read_yaml(directory / "sla.yaml")
    applications = _read_yaml(directory / "app_policy.yaml")
    workloads = _read_yaml(directory / "workloads.yaml")
    validate_policies(topology, sla, applications, workloads)
    return PolicyBundle(topology, sla, applications, workloads)


def validate_policies(
    topology: TopologyConfig, sla: Mapping[str, Any], applications: Mapping[str, Any],
    workloads: Mapping[str, Any],
) -> None:
    expected = {"sla": 3, "applications": 3, "workloads": 3}
    actual = {
        "sla": sla.get("schema_version"),
        "applications": applications.get("schema_version"),
        "workloads": workloads.get("schema_version"),
    }
    if actual != expected:
        raise ConfigurationError(f"policy schema mismatch: expected {expected}, got {actual}")
    if set(applications.get("paths", [])) != set(topology.underlays):
        raise ConfigurationError("application policy paths must match topology underlays")
    costs = applications.get("path_costs", {})
    if set(costs) != set(topology.underlays) or any(float(value) < 0 for value in costs.values()):
        raise ConfigurationError("path costs must cover every path with nonnegative values")
    classes = applications.get("classes")
    profiles = sla.get("profiles")
    if not isinstance(classes, dict) or not isinstance(profiles, dict) or set(classes) != set(profiles):
        raise ConfigurationError("application classes and SLA profiles must match")
    for name, rule in classes.items():
        if rule.get("mode") not in {"strict", "soft", "best-available"}:
            raise ConfigurationError(f"{name} has an invalid preference mode")
        preference = rule.get("preference")
        if not isinstance(preference, list) or set(preference) != set(topology.underlays):
            raise ConfigurationError(f"{name} must rank every path once")
        profile = profiles[name]
        required = {"maximum_rtt_ms", "maximum_jitter_ms", "maximum_loss_pct", "weights"}
        if not required.issubset(profile):
            raise ConfigurationError(f"SLA profile {name} is incomplete")
        weights = profile["weights"]
        required_weights = {"rtt", "jitter", "loss", "utilization", "cost"}
        if not required_weights.issubset(weights):
            raise ConfigurationError(f"SLA profile {name} has incomplete weights")
        expected_total = 1.0
        if abs(sum(float(value) for value in weights.values()) - expected_total) > 1e-6:
            raise ConfigurationError(f"SLA weights for {name} must sum to 1")
        if any(float(value) < 0 for value in weights.values()):
            raise ConfigurationError(f"SLA weights for {name} must be nonnegative")
    if int(sla.get("minimum_samples", 0)) <= 0 or int(sla.get("minimum_samples", 0)) > int(sla.get("window_size", 0)):
        raise ConfigurationError("minimum_samples must be within the SLA window")
    for field in ("policy_ttl_s", "failed_epochs_before_down", "hold_down_s", "minimum_path_time_s"):
        if float(sla.get(field, 0)) <= 0:
            raise ConfigurationError(f"{field} must be positive")
    if applications.get("unknown_class") not in classes:
        raise ConfigurationError("unknown_class is invalid")
    for mapping_name in ("applications", "categories"):
        mapping = applications.get(mapping_name, {})
        if not isinstance(mapping, dict) or any(value not in classes for value in mapping.values()):
            raise ConfigurationError(f"{mapping_name} references an invalid class")
    http = workloads.get("http", {})
    if int(http.get("file_size_mb", 0)) <= 0 or not http.get("client_counts"):
        raise ConfigurationError("HTTP workload requires a positive file and client counts")
    if not {1, 2, 3, 10}.issubset({int(value) for value in http["client_counts"]}):
        raise ConfigurationError("HTTP workload must include 1, 2, 3 and 10 concurrent flows")
    protocol_keys = {
        "iperf3_port", "tcp_echo_port", "udp_echo_port", "dns_port", "sip_port",
        "quic_port", "http_port", "https_port", "ssh_port", "ftp_port",
    }
    protocols = workloads.get("protocols", {})
    if not protocol_keys.issubset(protocols):
        raise ConfigurationError("protocol workload matrix is incomplete")
    if any(int(protocols[name]) <= 0 or int(protocols[name]) > 65535 for name in protocol_keys):
        raise ConfigurationError("protocol workload ports must be valid")


if __name__ == "__main__":
    bundle = load_bundle()
    print(
        f"valid: {len(bundle.topology.site_names)} routers, "
        f"{len(bundle.topology.underlays) + len(bundle.topology.spokes)} OpenFlow switches, "
        f"{len(bundle.applications['classes'])} application classes"
    )
