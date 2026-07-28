"""Versioned immutable policy snapshots consumed by edges and classifier control threads."""
from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Mapping


@dataclass(frozen=True)
class RankedPolicySnapshot:
    site: str
    version: int
    generation: str
    epoch: int
    created_at: float
    expires_at: float
    catalog_version: int
    ranked_paths: Mapping[str, tuple[str, ...]]
    applications: Mapping[str, str]
    categories: Mapping[str, str]
    unknown_class: str
    path_marks: Mapping[str, int]
    fail_mode: str

    def validate(self, valid_classes: set[str], valid_paths: set[str]) -> None:
        if self.version <= 0 or self.epoch < 0 or self.expires_at <= self.created_at:
            raise ValueError("policy version, epoch or lifetime is invalid")
        if self.fail_mode not in {"open", "closed"}:
            raise ValueError("policy fail_mode must be open or closed")
        if set(self.ranked_paths) != valid_classes:
            raise ValueError("policy must rank paths for every application class")
        if set(self.path_marks) != valid_paths:
            raise ValueError("policy path marks do not match configured paths")
        for class_name, paths in self.ranked_paths.items():
            if len(paths) != len(valid_paths) or set(paths) != valid_paths:
                raise ValueError(f"{class_name} must rank every path exactly once")
        if self.unknown_class not in valid_classes:
            raise ValueError("unknown class is invalid")
        if any(value not in valid_classes for value in self.applications.values()):
            raise ValueError("application mapping references an unknown class")

    def expired(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) >= self.expires_at

    def choose(self, application_class: str, healthy_paths: set[str]) -> str:
        ranking = self.ranked_paths.get(application_class, self.ranked_paths[self.unknown_class])
        return next((path for path in ranking if path in healthy_paths), ranking[0])

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 4,
            "site": self.site,
            "version": self.version,
            "generation": self.generation,
            "epoch": self.epoch,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
            "catalog_version": self.catalog_version,
            "ranked_paths": {key: list(value) for key, value in self.ranked_paths.items()},
            "applications": dict(self.applications),
            "categories": dict(self.categories),
            "unknown_class": self.unknown_class,
            "path_marks": dict(self.path_marks),
            "fail_mode": self.fail_mode,
        }


def snapshot_from_mapping(raw: Mapping[str, Any]) -> RankedPolicySnapshot:
    if int(raw.get("schema_version", 0)) != 4:
        raise ValueError("policy snapshot schema_version must be 4")
    return RankedPolicySnapshot(
        site=str(raw["site"]), version=int(raw["version"]),
        generation=str(raw["generation"]), epoch=int(raw["epoch"]),
        created_at=float(raw["created_at"]), expires_at=float(raw["expires_at"]),
        catalog_version=int(raw["catalog_version"]),
        ranked_paths={str(key): tuple(map(str, value)) for key, value in raw["ranked_paths"].items()},
        applications={str(key): str(value) for key, value in raw["applications"].items()},
        categories={str(key): str(value) for key, value in raw.get("categories", {}).items()},
        unknown_class=str(raw["unknown_class"]),
        path_marks={str(key): int(value) for key, value in raw["path_marks"].items()},
        fail_mode=str(raw["fail_mode"]),
    )
