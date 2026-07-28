import time

import pytest

from sdwan_v4.common.policy_model import snapshot_from_mapping


def sample() -> dict:
    now = time.time()
    return {
        "schema_version": 4, "site": "node1", "version": 4,
        "generation": "abc", "epoch": 9, "created_at": now,
        "expires_at": now + 30, "catalog_version": 1,
        "ranked_paths": {"web": ["bb", "mpls", "lte"], "unknown": ["mpls", "bb", "lte"]},
        "applications": {"HTTP": "web"}, "categories": {"Web": "web"},
        "unknown_class": "unknown", "path_marks": {"mpls": 1, "bb": 2, "lte": 3},
        "fail_mode": "open",
    }


def test_ranked_snapshot_and_local_health() -> None:
    policy = snapshot_from_mapping(sample())
    policy.validate({"web", "unknown"}, {"mpls", "bb", "lte"})
    assert policy.choose("web", {"mpls", "lte"}) == "mpls"


def test_incomplete_ranking_rejected() -> None:
    raw = sample()
    raw["ranked_paths"]["web"] = ["bb", "mpls"]
    with pytest.raises(ValueError):
        snapshot_from_mapping(raw).validate({"web", "unknown"}, {"mpls", "bb", "lte"})
