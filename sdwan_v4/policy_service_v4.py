#!/usr/bin/env python3
"""Central SD-WAN policy service; no packet payload processing."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
import hmac
import hashlib
import logging
import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping

from flask import Flask, jsonify, request

import requests

from .config_loader_v4 import PolicyBundle, load_bundle
from .desired_state_v4 import build_desired_states, initial_assignments
from .metrics_v4 import PathMetric
from .path_selection_v4 import EpochSLAEngine


LOG = logging.getLogger("sdwan.controller.v4")


@dataclass(frozen=True)
class ManualOverride:
    site: str
    application_class: str
    path: str
    created_at: float
    expires_at: float | None

    def active(self, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        return self.expires_at is None or now < self.expires_at


class ControllerCore:
    def __init__(self, bundle: PolicyBundle, token: str = ""):
        self.bundle = bundle
        self.config = bundle.topology
        self.token = token
        self.engine = EpochSLAEngine(bundle.sla, bundle.applications)
        self.assignments = initial_assignments(self.config)
        self.public_keys: dict[str, str] = {}
        self.epoch_buffer: dict[tuple[str, str, int], dict[str, PathMetric]] = defaultdict(dict)
        self.decisions: dict[str, dict[str, str]] = {}
        self.ranked_decisions: dict[str, dict[str, tuple[str, ...]]] = {}
        self.automatic_decisions: dict[str, dict[str, str]] = {}
        self.automatic_rankings: dict[str, dict[str, tuple[str, ...]]] = {}
        self.decision_reasons: dict[str, dict[str, str]] = {}
        self.overrides: dict[tuple[str, str], ManualOverride] = {}
        self.decision_version = 0
        self.reconcile_version = 0
        self.local_events: list[dict[str, Any]] = []
        self.metrics: dict[tuple[str, str, str], dict[str, Any]] = {}
        self.last_failover: dict[str, float] = {}
        self.connected_dpids: set[int] = set()
        self.lock = threading.RLock()
        config_bytes = b"".join(
            path.read_bytes() for path in sorted((Path(__file__).parent / "config").glob("*.yaml"))
        )
        self.generation = hashlib.sha256(config_bytes).hexdigest()[:16]

    @property
    def headers(self) -> dict[str, str]:
        return {"X-SDWAN-Token": self.token} if self.token else {}

    def edge_url(self, site: str, path: str) -> str:
        if site not in self.config.site_names:
            raise ValueError("unknown site")
        return f"http://{self.config.management_ip(site)}:{self.config.controller.edge_port}{path}"

    def defaults(self) -> dict[str, str]:
        return {
            name: str(rule["preference"][0])
            for name, rule in self.bundle.applications["classes"].items()
        }

    def default_rankings(self) -> dict[str, tuple[str, ...]]:
        return {
            name: tuple(map(str, rule["preference"]))
            for name, rule in self.bundle.applications["classes"].items()
        }

    def snapshot_payload(
        self, site: str, epoch: int, reasons: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        now = time.time()
        rankings = self.ranked_decisions.get(site, self.default_rankings())
        return {
            "schema_version": 4,
            "site": site,
            "active_hub": self.assignments[site],
            "version": max(self.decision_version, 1),
            "generation": self.generation,
            "epoch": max(epoch, 0),
            "created_at": now,
            "expires_at": now + float(self.bundle.sla.get("policy_ttl_s", 30)),
            "catalog_version": 1,
            "ranked_paths": {name: list(paths) for name, paths in rankings.items()},
            "decisions": self.decisions.get(site, self.defaults()),
            "reasons": dict(reasons or self.decision_reasons.get(site, {})),
            "applications": dict(self.bundle.applications["applications"]),
            "categories": dict(self.bundle.applications.get("categories", {})),
            "unknown_class": str(self.bundle.applications["unknown_class"]),
            "path_marks": {name: path.mark for name, path in self.config.underlays.items()},
            "fail_mode": self.config.settings.classifier_fail_mode,
        }

    def register(self, public_keys: Mapping[str, Any]) -> dict[str, Any]:
        keys = {str(site): str(key) for site, key in public_keys.items()}
        if set(keys) != set(self.config.site_names) or any(len(key) != 44 for key in keys.values()):
            raise ValueError("one 44-character WireGuard public key is required for every router")
        with self.lock:
            self.public_keys = keys
            self.reconcile_version += 1
            desired = build_desired_states(
                self.config, keys, self.assignments, self.reconcile_version,
            )
        return {
            "version": self.reconcile_version,
            "desired": {site: state.to_dict() for site, state in desired.items()},
        }

    def ingest_metric(self, payload: Mapping[str, Any]) -> dict[str, Any] | None:
        metric = PathMetric.from_dict(dict(payload))
        if metric.site not in self.config.spokes or metric.hub not in self.config.hubs:
            raise ValueError("metric has an unknown site or hub")
        if metric.underlay not in self.config.underlays:
            raise ValueError("metric has an unknown underlay")
        key = (metric.site, metric.hub, metric.epoch)
        with self.lock:
            bucket = self.epoch_buffer[key]
            if metric.underlay in bucket:
                raise ValueError("duplicate path metric in one epoch")
            bucket[metric.underlay] = metric
            self.metrics[(metric.site, metric.hub, metric.underlay)] = metric.to_dict()
            if set(bucket) != set(self.config.underlays):
                return None
            completed = dict(bucket)
            del self.epoch_buffer[key]
            decisions = self.engine.ingest_epoch(completed)
            selected = {name: value.path for name, value in decisions.items()}
            ranked = {name: value.ranked_paths for name, value in decisions.items()}
            reasons = {name: value.reason for name, value in decisions.items()}
            self.automatic_decisions[metric.site] = dict(selected)
            self.automatic_rankings[metric.site] = dict(ranked)
            self._expire_overrides()
            for (site, class_name), override in self.overrides.items():
                if site == metric.site and override.active():
                    selected[class_name] = override.path
                    ranked[class_name] = (override.path,) + tuple(
                        path for path in ranked[class_name] if path != override.path
                    )
                    reasons[class_name] = "manual override"
            self.decision_version += 1
            self.decisions[metric.site] = selected
            self.ranked_decisions[metric.site] = ranked
            self.decision_reasons[metric.site] = reasons
            return self.snapshot_payload(metric.site, metric.epoch, reasons)

    def _expire_overrides(self) -> None:
        now = time.time()
        self.overrides = {key: value for key, value in self.overrides.items() if value.active(now)}

    def expire_override_payloads(self, now: float | None = None) -> list[dict[str, Any]]:
        now = time.time() if now is None else now
        with self.lock:
            expired = [key for key, value in self.overrides.items() if not value.active(now)]
            affected: dict[str, list[str]] = defaultdict(list)
            for site, class_name in expired:
                del self.overrides[(site, class_name)]
                affected[site].append(class_name)
            payloads: list[dict[str, Any]] = []
            for site, classes in affected.items():
                selected = dict(self.decisions.get(site, self.defaults()))
                automatic = self.automatic_decisions.get(site, self.defaults())
                for class_name in classes:
                    selected[class_name] = automatic[class_name]
                    self.ranked_decisions.setdefault(site, self.default_rankings())[class_name] = (
                        self.automatic_rankings.get(site, self.default_rankings())[class_name]
                    )
                self.decision_version += 1
                self.decisions[site] = selected
                payloads.append(self.snapshot_payload(
                    site, 0, {name: "manual override expired" for name in classes},
                ))
            return payloads

    def set_override(
        self, site: str, application_class: str, path: str, ttl_s: float | None,
    ) -> dict[str, Any]:
        if site not in self.config.spokes:
            raise ValueError("override site must be a spoke")
        if application_class not in self.bundle.applications["classes"]:
            raise ValueError("unknown application class")
        if path not in self.config.underlays:
            raise ValueError("unknown path")
        if ttl_s is not None and (ttl_s <= 0 or ttl_s > 86400):
            raise ValueError("override ttl_s must be in (0, 86400]")
        now = time.time()
        override = ManualOverride(
            site, application_class, path, now, None if ttl_s is None else now + ttl_s,
        )
        with self.lock:
            self.overrides[(site, application_class)] = override
            selected = dict(self.decisions.get(site, self.defaults()))
            selected[application_class] = path
            self.decision_version += 1
            self.decisions[site] = selected
            rankings = dict(self.ranked_decisions.get(site, self.default_rankings()))
            rankings[application_class] = (path,) + tuple(
                item for item in rankings[application_class] if item != path
            )
            self.ranked_decisions[site] = rankings
            payload = self.snapshot_payload(site, 0, {application_class: "manual override"})
        return payload

    def release_override(self, site: str, application_class: str) -> dict[str, Any]:
        with self.lock:
            if self.overrides.pop((site, application_class), None) is None:
                raise ValueError("manual override does not exist")
            selected = dict(self.decisions.get(site, self.defaults()))
            selected[application_class] = self.automatic_decisions.get(
                site, self.defaults()
            )[application_class]
            self.decision_version += 1
            self.decisions[site] = selected
            self.ranked_decisions.setdefault(site, self.default_rankings())[application_class] = (
                self.automatic_rankings.get(site, self.default_rankings())[application_class]
            )
            return self.snapshot_payload(
                site, 0, {application_class: "manual override released"},
            )

    def record_local_event(self, payload: Mapping[str, Any]) -> None:
        required = {"site", "event", "slot", "physical_path", "version", "timestamp"}
        if not required.issubset(payload) or payload["site"] not in self.config.spokes:
            raise ValueError("invalid local event")
        with self.lock:
            self.local_events.append(dict(payload))
            self.local_events = self.local_events[-200:]

    def post_edge(self, site: str, path: str, payload: Mapping[str, Any], timeout: float = 3) -> dict[str, Any]:
        response = requests.post(
            self.edge_url(site, path), json=dict(payload), headers=self.headers, timeout=timeout,
        )
        response.raise_for_status()
        return response.json()

    def deliver_decision(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        return self.post_edge(str(payload["site"]), "/sdwan/decision", payload)

    def initial_reconcile(self, registration: Mapping[str, Any]) -> None:
        desired = registration["desired"]
        # Hubs first so all receivers exist before spokes dial them.
        for site in (*self.config.hubs, *self.config.spokes):
            self.post_edge(site, "/sdwan/reconcile", desired[site], timeout=8)

    def failover(self, spoke: str, new_hub: str) -> dict[str, Any]:
        """Transactional Phase-1 hub failover with three-overlay verification.

        Phase 1 has one WG interface per transport, so it cannot be fully
        make-before-break at the spoke. Phase 2's separate (hub,path) interfaces
        are documented in MIGRATION.md.
        """
        if spoke not in self.config.spokes or new_hub not in self.config.hubs:
            raise ValueError("invalid spoke or hub")
        if not self.public_keys:
            raise RuntimeError("routers must register before hub failover")
        with self.lock:
            old_hub = self.assignments[spoke]
            if old_hub == new_hub:
                return {"status": "unchanged", "spoke": spoke, "active_hub": new_hub}
            before = dict(self.assignments)
            after = dict(before)
            after[spoke] = new_hub
            self.reconcile_version += 1
            version = self.reconcile_version
            target = build_desired_states(self.config, self.public_keys, after, version)
            rollback_version = version + 1
            rollback = build_desired_states(self.config, self.public_keys, before, rollback_version)
        applied: list[str] = []
        try:
            for site in (old_hub, new_hub, spoke):
                self.post_edge(site, "/sdwan/reconcile", target[site].to_dict(), timeout=8)
                applied.append(site)
            verification = self.post_edge(spoke, "/sdwan/probe", {"hub": new_hub}, timeout=20)["metrics"]
            if set(item["underlay"] for item in verification) != set(self.config.underlays):
                raise RuntimeError("new hub did not return all overlay tests")
            if any(not item["overlay_reachable"] for item in verification):
                raise RuntimeError("one or more new-hub overlays failed")
        except (requests.RequestException, KeyError, RuntimeError) as exc:
            rollback_errors: list[str] = []
            for site in reversed(applied):
                try:
                    self.post_edge(site, "/sdwan/reconcile", rollback[site].to_dict(), timeout=8)
                except requests.RequestException as rollback_exc:
                    rollback_errors.append(f"{site}: {rollback_exc}")
            raise RuntimeError(f"hub failover failed: {exc}; rollback={rollback_errors or 'ok'}") from exc
        with self.lock:
            self.assignments[spoke] = new_hub
            self.reconcile_version = version
            self.last_failover[spoke] = time.time()
        return {
            "status": "applied", "spoke": spoke, "old_hub": old_hub,
            "new_hub": new_hub, "version": version, "verification": verification,
        }

    def policy(self, site: str) -> dict[str, Any]:
        if site not in self.config.spokes:
            raise ValueError("unknown spoke")
        payload = self.snapshot_payload(site, 0)
        payload.update({
            "overrides": [
                asdict(value) for key, value in self.overrides.items()
                if key[0] == site and value.active()
            ],
        })
        return payload

    def state(self, site: str) -> dict[str, Any]:
        return {
            "policy": self.policy(site),
            "openflow": {"connected_dpids": sorted(self.connected_dpids)},
            "metrics": [value for key, value in self.metrics.items() if key[0] == site],
            "local_events": [value for value in self.local_events if value["site"] == site],
        }



def create_app(bundle: PolicyBundle | None = None, token: str | None = None) -> Flask:
    bundle = bundle or load_bundle()
    token = os.getenv(bundle.topology.controller.shared_token_env, "") if token is None else token
    core = ControllerCore(bundle, token)
    app = Flask("sdwan-v4-policy")
    app.config["core"] = core

    @app.before_request
    def authenticate() -> Any:
        if request.path == "/healthz":
            return None
        supplied = request.headers.get("X-SDWAN-Token", "")
        if token and not hmac.compare_digest(token, supplied):
            return jsonify({"error": "unauthorized"}), 401
        return None

    @app.get("/healthz")
    def healthz() -> Any:
        return jsonify({"healthy": True, "component": "policy-service", "schema_version": 4})

    @app.post("/sdwan/register")
    def register() -> Any:
        try:
            result = core.register((request.get_json(force=True) or {})["public_keys"])
            for site, desired in result["desired"].items():
                core.post_edge(site, "/sdwan/reconcile", desired, timeout=8)
            return jsonify({"registered": sorted(result["desired"]), "version": result["version"]}), 202
        except (KeyError, ValueError, requests.RequestException) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/sdwan/metrics")
    def metrics() -> Any:
        try:
            decision = core.ingest_metric(request.get_json(force=True) or {})
            if decision:
                core.deliver_decision(decision)
            return jsonify({"accepted": True, "decision": decision}), 202
        except (ValueError, requests.RequestException) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/sdwan/local-event")
    def local_event() -> Any:
        payload = request.get_json(force=True) or {}
        if payload.get("site") not in core.config.spokes:
            return jsonify({"error": "invalid site"}), 400
        with core.lock:
            core.local_events.append(dict(payload))
            core.local_events[:] = core.local_events[-1000:]
        return jsonify({"accepted": True}), 202

    @app.get("/sdwan/state/<site>")
    def state(site: str) -> Any:
        try:
            return jsonify(core.state(site))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 404

    @app.post("/sdwan/override")
    def override() -> Any:
        payload = request.get_json(force=True) or {}
        try:
            update = core.set_override(
                str(payload["site"]), str(payload["application_class"]), str(payload["path"]),
                None if payload.get("ttl_s") is None else float(payload["ttl_s"]),
            )
            core.deliver_decision(update)
            return jsonify(update), 202
        except (KeyError, ValueError, requests.RequestException) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.delete("/sdwan/override/<site>/<application_class>")
    def delete_override(site: str, application_class: str) -> Any:
        try:
            update = core.release_override(site, application_class)
            core.deliver_decision(update)
            return jsonify(update), 202
        except (ValueError, requests.RequestException) as exc:
            return jsonify({"error": str(exc)}), 400

    @app.post("/sdwan/failover")
    def failover() -> Any:
        payload = request.get_json(force=True) or {}
        try:
            return jsonify(core.failover(str(payload["spoke"]), str(payload["new_hub"])))
        except (KeyError, ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 409

    @app.post("/sdwan/underlay-stats")
    def underlay_stats() -> Any:
        payload = request.get_json(force=True) or {}
        with core.lock:
            core.local_events.append({"site": "underlay", "kind": "ryu-port-stats", "payload": payload})
            core.local_events[:] = core.local_events[-1000:]
        return jsonify({"accepted": True}), 202

    @app.post("/sdwan/openflow-state")
    def openflow_state() -> Any:
        payload = request.get_json(force=True) or {}
        try:
            connected = {int(value) for value in payload["connected_dpids"]}
        except (KeyError, TypeError, ValueError):
            return jsonify({"error": "connected_dpids must be an integer list"}), 400
        with core.lock:
            core.connected_dpids = connected
        return jsonify({"accepted": True, "connected_dpids": sorted(connected)}), 202

    return app


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="SD-WAN v4 policy service")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()
    create_app().run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
