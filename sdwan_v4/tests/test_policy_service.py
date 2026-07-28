from sdwan_v4.policy_service_v4 import ControllerCore, create_app


def test_policy_snapshot_is_ranked_and_expiring(bundle) -> None:
    payload = ControllerCore(bundle).snapshot_payload("node1", 0)
    assert payload["schema_version"] == 4
    assert payload["expires_at"] > payload["created_at"]
    assert all(set(paths) == {"mpls", "bb", "lte"} for paths in payload["ranked_paths"].values())


def test_policy_health_does_not_require_edge_or_ryu(bundle) -> None:
    response = create_app(bundle, token="").test_client().get("/healthz")
    assert response.status_code == 200
    assert response.get_json()["component"] == "policy-service"
