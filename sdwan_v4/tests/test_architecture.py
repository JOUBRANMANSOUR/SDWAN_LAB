from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_python_is_not_in_the_nfqueue_hot_path() -> None:
    edge = (ROOT / "edge_agent_v4.py").read_text()
    controller = (ROOT / "controller_v4.py").read_text()
    assert "NetfilterQueue" not in edge
    assert "ctypes" not in edge
    assert "ndpi" not in controller.lower()


def test_fallback_is_marked_before_queue_and_saved_after_verdict() -> None:
    source = (ROOT / "edge_agent_v4.py").read_text()
    fallback = source.index("assign explicit provisional fallback")
    queue = source.index("attach outbound NFQUEUE")
    save = source.index("save outbound mark")
    assert fallback < queue < save


def test_non_quic_udp_443_is_an_explicit_negative_fixture() -> None:
    fixture = (ROOT / "workloads" / "protocol_fixtures.py").read_text()
    matrix = (ROOT / "workloads" / "run_protocol_matrix.sh").read_text()
    assert "udp443-nonquic" in fixture and "udp443-nonquic" in matrix
    assert "quic-like" not in fixture and "quic-like" not in matrix
