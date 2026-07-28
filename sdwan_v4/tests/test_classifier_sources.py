from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_native_classifier_uses_ndpi_5_state_and_native_confidence() -> None:
    source = (ROOT / "classifier" / "nfqueue_worker.c").read_text()
    engine = (ROOT / "classifier" / "ndpi_engine.c").read_text()
    assert "NDPI_STATE_CLASSIFIED" in source
    assert "NDPI_STATE_MONITORING" in source
    assert "flow->ndpi->confidence" not in source
    assert "ndpi_flow_free(flow)" in engine
    assert "result.protocol_stack" in engine
    assert "ndpi_confidence_get_name" in engine
    assert "ndpi_extra_dissection_possible" not in engine
    assert "ctypes" not in source


def test_queue_overflow_fail_open_is_explicit() -> None:
    source = (ROOT / "classifier" / "nfqueue_worker.c").read_text()
    assert "NFQA_CFG_F_FAIL_OPEN" in source
    assert "NFQA_CFG_F_GSO" in source
    assert "NFQA_CAP_LEN" in source
    assert "NFQA_SKB_INFO" in source
    assert "mnl_socket_recvfrom" in source
    assert "NETLINK_NO_ENOBUFS" not in source


def test_established_tcp_and_udp_flows_remain_pinned() -> None:
    source = (ROOT / "classifier" / "nfqueue_worker.c").read_text()
    assert "created && identified && terminal" in source
    assert source.count("flow->active_path = flow->desired_path") == 1
    assert "packet.protocol == IPPROTO_UDP" not in source.split(
        "flow->active_path = flow->desired_path"
    )[1]
    assert "flow->desired_path = sdwan_policy_choose" in source
