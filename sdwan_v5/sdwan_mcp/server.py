"""Official MCP SDK server for local stdio-only SD-WAN evidence queries."""
from __future__ import annotations
import os
from typing import Annotated, Any, Callable, Dict, List, Optional
from pydantic import Field, IPvAnyAddress
from mcp.server.fastmcp import FastMCP
from sdwan_v5.management.auth import Principal, allowed, verify_agent_context
from sdwan_v5.management.config import ManagementConfig
from sdwan_v5.management.service import ManagementService
from .models.common import OperationalResult, StateKind, UnknownField, result_from_payload

MAX_ITEMS = 100

def _bounded(value: Any, limit: int = MAX_ITEMS) -> tuple[Any, bool, int]:
    """Apply structural list limits before serialization; never slice JSON text."""
    if isinstance(value, list):
        total = len(value)
        return value[:limit], total > limit, total
    if isinstance(value, dict):
        result: Dict[str, Any] = {}
        truncated = False
        total = 0
        for key, item in value.items():
            bounded, was_truncated, count = _bounded(item, limit)
            result[key] = bounded
            truncated = truncated or was_truncated
            total = max(total, count)
        return result, truncated, total
    return value, False, 0

def _tool_result(service: ManagementService, principal: Principal, name: str, payload: Dict[str, Any], source_type: str, state_kind: StateKind, *, unavailable_reason: Optional[str] = None) -> OperationalResult:
    bounded, truncated, total = _bounded(payload)
    available = unavailable_reason is None and payload.get("available", payload.get("availability", "AVAILABLE")) not in (False, "UNAVAILABLE")
    unknowns: List[UnknownField] = []
    for item in bounded.get("unknowns", []) if isinstance(bounded, dict) else []:
        if isinstance(item, dict) and item.get("field") and item.get("reason"):
            unknowns.append(UnknownField(field=str(item["field"]), reason=str(item["reason"])))
    if unavailable_reason:
        unknowns.append(UnknownField(field="result", reason=unavailable_reason))
    result = result_from_payload(name, bounded if isinstance(bounded, dict) else {"value": bounded}, source_type, state_kind, available=available, limitations=list(payload.get("limitations", [])) if isinstance(payload, dict) else [], warnings=list(payload.get("warnings", [])) if isinstance(payload, dict) else [], unknowns=unknowns)
    result.truncated = truncated
    result.returned_count = min(total, MAX_ITEMS) if total else len(result.facts)
    result.total_count = total if total else len(result.facts)
    result.next_cursor = "offset:{}".format(MAX_ITEMS) if truncated else None
    service.audit.add(principal.subject, "MCP_TOOL", name, "200" if available else "UNAVAILABLE")
    bundle_id = os.environ.get("SDWAN_EVIDENCE_BUNDLE_ID", "")
    if bundle_id:
        service.audit.append_evidence_tool(bundle_id, name, {}, result.model_dump(mode="json"))
    return result

def _require(principal: Principal, scope: str) -> None:
    if not allowed(principal, "mcp:read") or not allowed(principal, scope):
        raise PermissionError("PERMISSION_DENIED: required read-only scope is not granted")

def _site(service: ManagementService, name: str) -> None:
    if name not in service.topology.site_names:
        raise ValueError("UNKNOWN_SITE: requested site is not configured; use list_sites")

def _hub(service: ManagementService, name: str) -> None:
    if name not in service.topology.hubs:
        raise ValueError("UNKNOWN_HUB: requested hub is not configured")

def build_server(config: ManagementConfig, principal: Principal) -> FastMCP:
    """Build a per-process authorized FastMCP server. No HTTP transport is enabled."""
    service = ManagementService(config)
    mcp = FastMCP("sdwan-management-mcp", instructions="Local stdio-only, read-only SD-WAN evidence server. Every current-state result is provenance tagged.")

    @mcp.tool(description="Return a bounded, read-only inventory summary: service health, configured topology, sites, desired-state summaries, ownership, enrolled devices, and destination-policy metadata. Use for an overview; do not use it for a route decision or live tunnel detail. Runtime data may be unavailable. Every value is tagged with provenance in structuredContent.")
    def get_dashboard_summary() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_dashboard_summary", service.dashboard(), "database", StateKind.configured)

    @mcp.tool(description="Return configured site records from the policy database. Use to discover valid site identifiers and their configured LAN and hub assignments. Do not use for live status, tunnels, or selected routes. Database state is not live runtime observation; unavailable data is represented by metadata. Takes no input.")
    def list_sites() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "list_sites", {"sites": service.sites()}, "database", StateKind.configured)

    @mcp.tool(description="Return the compact configured record for one site: LAN prefix, preferred hub, standby hub, and configured status. Use for questions about a site's configured identity or LAN prefix. Do not use it for routes or tunnels; use get_site_routes or get_site_tunnels for those live details. Takes one configured site identifier.")
    def get_site_status(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier, for example node1")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_status", service.site_status(site), "database", StateKind.configured)

    @mcp.tool(description="Return observed WireGuard text status for one configured site through the constrained runtime adapter. Use only for current tunnel inspection. Do not use it for routing-table decisions or to expose private keys. If Docker or the namespace is unavailable, metadata reports unavailable rather than inventing tunnel state.")
    def get_site_tunnels(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_tunnels", {"site": site, "tunnels": service.runtime_view(site).get("tunnels")}, "wireguard", StateKind.observed)

    @mcp.tool(description="Return bounded observed route groups and policy rules for one configured site. Use to list routing rules, tables, prefixes, next hops, and output interfaces. Do not use it to determine the route for one destination; use explain_route_decision with destination. Missing values are represented as unknown metadata and never inferred.")
    def get_site_routes(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "get_site_routes", service.route_summary(site), "routing_table", StateKind.observed)

    @mcp.tool(description="Return static topology configuration: management network, configured hubs and sites, transports, and configured data-center, SaaS, and Cloud VPC values. Use for configuration questions only. Do not use it as proof of runtime reachability or live tunnel state. Takes no input.")
    def get_topology() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_topology", service.topology_view(), "configuration", StateKind.configured)

    @mcp.tool(description="Return configured and runtime information for one hub. Use for hub status questions. Do not use for a spoke route lookup; explain_route_decision requires a site and destination. Runtime information can be unavailable.")
    def get_hub_status(hub: Annotated[str, Field(min_length=1, max_length=64, description="Configured hub identifier, for example hub1")]) -> OperationalResult:
        _require(principal, "network:read"); _hub(service, hub)
        return _tool_result(service, principal, "get_hub_status", service.hub_view(hub), "runtime_command", StateKind.observed)

    @mcp.tool(description="Return configured Cloud VPC status, network, endpoint, and configured gateways. Use for Cloud VPC configuration status. Do not use as proof that a Cloud VPC path is currently reachable; runtime availability is returned separately. Takes no input.")
    def get_cloud_status() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_cloud_status", service.network_view("cloud-vpc"), "configuration", StateKind.configured)

    @mcp.tool(description="Return configured SaaS network and endpoint information. Use for configured SaaS inventory. Do not use it as a live HTTP reachability check because this tool has no active probe adapter. Takes no input.")
    def get_saas_status() -> OperationalResult:
        _require(principal, "network:read")
        return _tool_result(service, principal, "get_saas_status", service.network_view("saas"), "configuration", StateKind.configured)

    @mcp.tool(description="Compare desired database state and observed runtime state for one configured site in Python. Use when asking whether requested state agrees with available live evidence. Do not infer missing runtime values as mismatches; comparison entries identify unavailable and non-comparable fields.")
    def compare_desired_actual(site: Annotated[str, Field(min_length=1, max_length=64, description="Configured site identifier")]) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        return _tool_result(service, principal, "compare_desired_actual", service.compare_desired_actual(site), "derived", StateKind.derived)

    @mcp.tool(description="Perform a verified read-only route lookup for one site and destination. Use when the question is about the rule, table, next hop, output interface, hub, or transport selected for that destination. Do not use it to list all routes. The optional source and fwmark are passed to the runtime lookup; omitted values remain unavailable. Hub and transport, when shown, are explicitly derived from the observed interface name.")
    def explain_route_decision(site: Annotated[str, Field(min_length=1, max_length=64)], destination: IPvAnyAddress, source: Optional[IPvAnyAddress] = None, fwmark: Optional[int] = Field(default=None, ge=0)) -> OperationalResult:
        _require(principal, "network:read"); _site(service, site)
        data = service.route_decision_report(site, str(destination), str(source) if source is not None else None, fwmark)
        if not data.get("available"):
            raise ValueError("RUNTIME_UNAVAILABLE: {}".format(data.get("reason", "route lookup unavailable")))
        return _tool_result(service, principal, "explain_route_decision", data, "routing_table", StateKind.observed)

    @mcp.tool(description="Return bounded read-only management and policy audit events. Use for recent recorded events, not for current route or tunnel status. Event history can be incomplete because it is intentionally bounded. Takes no input and requires audit-read authorization.")
    def get_recent_events() -> OperationalResult:
        _require(principal, "audit:read")
        return _tool_result(service, principal, "get_recent_events", {"events": service.combined_events()}, "audit_log", StateKind.observed)

    return mcp

def main() -> int:
    config = ManagementConfig.from_env()
    session_id = os.environ.get("SDWAN_CHAT_SESSION_ID", "")
    token = os.environ.get("SDWAN_AGENT_CONTEXT_TOKEN", "")
    try:
        principal = verify_agent_context(config.signing_secret, token, session_id, os.environ.get("SDWAN_AGENT_CONTEXT_AUDIENCE", config.agent_context_audience), config.agent_context_ttl_seconds)
    except ValueError:
        return 2
    build_server(config, principal).run(transport="stdio")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
