"""Complete-epoch SLA and optional capacity-aware path selection."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import math
import time
from typing import Any, Mapping

from .metrics_v4 import PathMetric


@dataclass(frozen=True)
class PathDecision:
    site: str
    hub: str
    application_class: str
    path: str
    ranked_paths: tuple[str, ...]
    version: int
    reason: str
    score: float
    timestamp: float


@dataclass
class _Selection:
    path: str
    since: float
    last_change: float
    bad_epochs: int = 0


class EpochSLAEngine:
    """Ingest all paths in one epoch, then increment hysteresis exactly once."""

    def __init__(self, sla: Mapping[str, Any], application_policy: Mapping[str, Any]):
        self.sla = sla
        self.policy = application_policy
        self.window_size = int(sla["window_size"])
        self.minimum_samples = int(sla["minimum_samples"])
        self.failed_epochs = int(sla["failed_epochs_before_down"])
        self.windows: dict[tuple[str, str, str], deque[PathMetric]] = defaultdict(
            lambda: deque(maxlen=self.window_size)
        )
        self.selections: dict[tuple[str, str, str], _Selection] = {}
        self.version = 0
        self.last_epoch: dict[tuple[str, str], int] = {}

    def ingest_epoch(self, metrics: Mapping[str, PathMetric], now: float | None = None) -> dict[str, PathDecision]:
        if set(metrics) != set(self.policy["paths"]):
            raise ValueError("measurement epoch must contain every configured path exactly once")
        values = list(metrics.values())
        site_hub = {(value.site, value.hub) for value in values}
        epochs = {value.epoch for value in values}
        if len(site_hub) != 1 or len(epochs) != 1:
            raise ValueError("measurement epoch mixes site, hub or epoch identifiers")
        site, hub = next(iter(site_hub))
        epoch = next(iter(epochs))
        if epoch <= self.last_epoch.get((site, hub), -1):
            raise ValueError("stale or duplicate measurement epoch")
        self.last_epoch[(site, hub)] = epoch
        for path, metric in metrics.items():
            if path != metric.underlay:
                raise ValueError("metric key does not match its underlay")
            self.windows[(site, hub, path)].append(metric)
        now = time.monotonic() if now is None else now
        return {
            class_name: self._decide(site, hub, class_name, now)
            for class_name in self.policy["classes"]
        }

    def _summary(self, site: str, hub: str, path: str) -> dict[str, float | bool]:
        window = list(self.windows[(site, hub, path)])
        usable = [
            item for item in window
            if item.rtt_avg_ms is not None and item.jitter_ms is not None
        ]
        if len(usable) < self.minimum_samples:
            return {"healthy": False, "rtt": math.inf, "jitter": math.inf, "loss": 100.0,
                    "utilization": 100.0, "available": 0.0}
        handshake_limit = float(self.sla["handshake_max_age_s"])
        latest = window[-1]
        healthy = (
            latest.link_up and latest.underlay_reachable and latest.overlay_reachable
            and (
                latest.wireguard_handshake_age_s is None
                or latest.wireguard_handshake_age_s <= handshake_limit
            )
        )
        alpha = float(self.sla.get("utilization_ewma_alpha", 0.25))
        utilization = float(usable[0].utilization_pct)
        for item in usable[1:]:
            utilization = alpha * float(item.utilization_pct) + (1.0 - alpha) * utilization
        return {
            "healthy": healthy,
            "rtt": fmean(item.rtt_avg_ms for item in usable if item.rtt_avg_ms is not None),
            "jitter": fmean(item.jitter_ms for item in usable if item.jitter_ms is not None),
            "loss": fmean(item.loss_pct for item in usable),
            "utilization": utilization,
            "available": fmean(item.available_mbps for item in usable),
        }

    def _score(self, site: str, hub: str, path: str, class_name: str) -> tuple[bool, float, str]:
        summary = self._summary(site, hub, path)
        profile = self.sla["profiles"][class_name]
        rule = self.policy["classes"][class_name]
        within = bool(summary["healthy"]) and (
            float(summary["rtt"]) <= float(profile["maximum_rtt_ms"])
            and float(summary["jitter"]) <= float(profile["maximum_jitter_ms"])
            and float(summary["loss"]) <= float(profile["maximum_loss_pct"])
        )
        if rule.get("capacity_aware", False):
            within = within and float(summary["utilization"]) <= float(profile.get("maximum_utilization_pct", 95))
        weights = profile["weights"]
        score = (
            float(weights["rtt"]) * float(summary["rtt"]) / float(profile["maximum_rtt_ms"])
            + float(weights["jitter"]) * float(summary["jitter"]) / float(profile["maximum_jitter_ms"])
            + float(weights["loss"]) * float(summary["loss"]) / max(float(profile["maximum_loss_pct"]), 0.01)
        )
        score += float(weights.get("utilization", 0.0)) * float(summary["utilization"]) / 100.0
        costs = self.policy.get("path_costs", {})
        max_cost = max((float(value) for value in costs.values()), default=1.0)
        path_cost = float(costs.get(path, 0.0))
        score += float(weights.get("cost", 0.0)) * path_cost / max(max_cost, 0.001)
        rank = rule["preference"].index(path)
        if rule["mode"] == "strict":
            score += rank * 1000.0
        elif rule["mode"] == "soft":
            score += rank * float(rule.get("preference_penalty", 0.15))
        reason = (
            f"rtt={float(summary['rtt']):.1f}ms jitter={float(summary['jitter']):.1f}ms "
            f"loss={float(summary['loss']):.1f}% utilization-ewma="
            f"{float(summary['utilization']):.1f}% available-estimate="
            f"{float(summary['available']):.1f}Mbps cost={path_cost:.2f}"
        )
        return within, score, reason

    def _decide(self, site: str, hub: str, class_name: str, now: float) -> PathDecision:
        paths = list(self.policy["classes"][class_name]["preference"])
        scored = {path: self._score(site, hub, path, class_name) for path in paths}
        eligible = [path for path in paths if scored[path][0]]
        candidate = min(eligible or paths, key=lambda path: scored[path][1])
        ordered = sorted(paths, key=lambda path: (not scored[path][0], scored[path][1]))
        key = (site, hub, class_name)
        current = self.selections.get(key)
        changed = current is None
        prefix = "initial"
        if current is None:
            current = _Selection(candidate, now, now)
            self.selections[key] = current
        else:
            current_healthy = scored[current.path][0]
            current.bad_epochs = 0 if current_healthy else current.bad_epochs + 1
            elapsed = now - current.since
            since_change = now - current.last_change
            if candidate != current.path and not current_healthy:
                if current.bad_epochs >= self.failed_epochs and since_change >= float(self.sla["hold_down_s"]):
                    changed, prefix = True, "SLA failure"
            elif candidate != current.path and elapsed >= float(self.sla["minimum_path_time_s"]):
                improvement = 100.0 * (scored[current.path][1] - scored[candidate][1]) / max(scored[current.path][1], 0.001)
                if since_change >= float(self.sla["hold_down_s"]) and improvement >= float(self.sla["switch_improvement_pct"]):
                    changed, prefix = True, f"{improvement:.1f}% score improvement"
            if changed:
                current.path, current.since, current.last_change, current.bad_epochs = candidate, now, now, 0
        if changed:
            self.version += 1
        ranked = (current.path,) + tuple(path for path in ordered if path != current.path)
        return PathDecision(
            site, hub, class_name, current.path, ranked, self.version,
            f"{prefix}: {scored[current.path][2]}", scored[current.path][1], now,
        )


def fmean(values: object) -> float:
    materialized = list(values)  # type: ignore[arg-type]
    return sum(float(value) for value in materialized) / len(materialized)

