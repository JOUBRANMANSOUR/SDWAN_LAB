from sdwan_v4.metrics_v4 import PathMetric
from sdwan_v4.path_selection_v4 import EpochSLAEngine


def metric(path: str, epoch: int, rtt: float, utilization: float) -> PathMetric:
    return PathMetric(
        site="node1", hub="hub1", underlay=path, epoch=epoch,
        link_up=True, underlay_reachable=True, overlay_reachable=True,
        rtt_min_ms=rtt, rtt_avg_ms=rtt, rtt_max_ms=rtt, jitter_ms=1.0,
        loss_pct=0.0, wireguard_handshake_age_s=1.0, tx_mbps=0.0, rx_mbps=0.0,
        available_mbps=50.0 * (1 - utilization / 100),
        utilization_pct=utilization, queue_drops=0, queue_backlog_bytes=0,
        active_flows=1, tcp_retransmissions=0, timestamp=f"epoch-{epoch}",
    )


def test_engine_returns_complete_rankings(bundle) -> None:
    engine = EpochSLAEngine(bundle.sla, bundle.applications)
    result = None
    for epoch in range(1, 4):
        result = engine.ingest_epoch({
            "mpls": metric("mpls", epoch, 10, 20),
            "bb": metric("bb", epoch, 30, 10),
            "lte": metric("lte", epoch, 70, 30),
        }, now=float(epoch))
    assert result is not None
    assert set(result["normal-web"].ranked_paths) == {"mpls", "bb", "lte"}
