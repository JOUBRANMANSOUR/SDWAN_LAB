"""Path-quality and capacity metrics grouped into complete measurement epochs."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import re
from statistics import fmean


RTT_RE = re.compile(r"time[=<]([0-9.]+)\s*ms")


def average_absolute_rtt_difference(samples: list[float]) -> float:
    if len(samples) < 2:
        return 0.0
    return fmean(abs(right - left) for left, right in zip(samples, samples[1:]))


@dataclass(frozen=True)
class PathMetric:
    epoch: int
    site: str
    hub: str
    underlay: str
    link_up: bool
    underlay_reachable: bool
    overlay_reachable: bool
    rtt_avg_ms: float | None
    rtt_min_ms: float | None
    rtt_max_ms: float | None
    jitter_ms: float | None
    loss_pct: float
    wireguard_handshake_age_s: float | None
    tx_mbps: float = 0.0
    rx_mbps: float = 0.0
    utilization_pct: float = 0.0
    available_mbps: float = 0.0
    queue_drops: int = 0
    queue_backlog_bytes: int = 0
    active_flows: int = 0
    tcp_retransmissions: int = 0
    latest_successful_probe_time: str | None = None
    timestamp: str = ""

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "PathMetric":
        return cls(**value)  # type: ignore[arg-type]


def metric_from_ping(
    *, epoch: int, site: str, hub: str, underlay: str, output: str,
    transmitted: int, underlay_reachable: bool, overlay_reachable: bool,
    handshake_age_s: float | None, capacity_mbps: float, tx_mbps: float = 0.0,
    rx_mbps: float = 0.0, queue_drops: int = 0, queue_backlog_bytes: int = 0,
    active_flows: int = 0, tcp_retransmissions: int = 0,
) -> PathMetric:
    samples = [float(value) for value in RTT_RE.findall(output)]
    received = len(samples)
    loss = 100.0 if transmitted <= 0 else 100.0 * (transmitted - received) / transmitted
    timestamp = datetime.now(timezone.utc).isoformat()
    load = max(tx_mbps, rx_mbps)
    return PathMetric(
        epoch, site, hub, underlay, underlay_reachable and overlay_reachable,
        underlay_reachable, overlay_reachable,
        fmean(samples) if samples else None, min(samples) if samples else None,
        max(samples) if samples else None,
        average_absolute_rtt_difference(samples) if samples else None,
        max(0.0, min(100.0, loss)), handshake_age_s, tx_mbps, rx_mbps,
        min(100.0, 100.0 * load / max(capacity_mbps, 0.001)),
        max(0.0, capacity_mbps - load), queue_drops, queue_backlog_bytes,
        active_flows, tcp_retransmissions,
        timestamp if underlay_reachable and overlay_reachable else None, timestamp,
    )


