def test_required_topology(bundle) -> None:
    assert set(bundle.topology.hubs) == {"hub1", "hub2"}
    assert set(bundle.topology.spokes) == {f"node{i}" for i in range(1, 6)}
    assert set(bundle.topology.underlays) == {"mpls", "bb", "lte"}
    assert bundle.topology.settings.nfqueue_start < bundle.topology.settings.nfqueue_end
    assert all(not rule["move_udp_on_final_classification"] for rule in bundle.applications["classes"].values())
