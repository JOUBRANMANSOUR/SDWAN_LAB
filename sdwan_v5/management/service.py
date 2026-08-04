"""Shared read-only query layer used by REST, MCP, and the Agent Gateway."""
from __future__ import annotations
from typing import Any
from ..common.model import load_config
from ..topology_v5 import build_live_plan
from .config import ManagementConfig
from .repository import ReadOnlyState, AuditStore
from .runtime import RuntimeAdapter

class ManagementService:
    def __init__(self, config: ManagementConfig):
        self.config, self.topology = config, load_config(config.topology)
        self.state, self.audit = ReadOnlyState(config.policy_db, config.ztp_db), AuditStore(config.state_dir)
        self.runtime = RuntimeAdapter(self.topology)
    def health(self) -> dict[str, Any]:
        return {"status":"ok", "mode":"read-only", "sources":{"topology":"AVAILABLE", "policy_db":"AVAILABLE" if self.config.policy_db.is_file() else "UNAVAILABLE", "ztp_db":"AVAILABLE" if self.config.ztp_db.is_file() else "UNAVAILABLE", "runtime":"UNAVAILABLE (adapter not configured)"}}
    def topology_view(self) -> dict[str, Any]:
        c=self.topology
        return {"management_network":str(c.management_network), "hubs":[{"name":h.name,"management_ip":str(h.management_ip)} for h in c.hubs.values()], "sites":[{"name":s.name,"lan":str(s.lan_network),"preferred_hub":s.preferred_hub,"standby_hub":s.standby_hub} for s in c.sites.values()], "transports":[{"name":t.name,"network":str(t.network),"internet_capable":t.internet_capable,"table":t.route_table} for t in c.transports.values()], "data_center":{"network":str(c.data_center_network),"app_ip":str(c.data_center_app_ip)}, "saas":{"network":str(c.saas_network),"app_ip":str(c.saas_ip)}, "cloud_vpc":{"enabled":c.cloud_vpc.enabled,"network":str(c.cloud_vpc.network)}}
    def sites(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT site,device_id,lan_prefix,preferred_hub,standby_hub,status,updated_at FROM sites ORDER BY site")
    def ownership(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT prefix,spoke,preferred_hub,standby_hub,current_owner_hub,previous_owner_hub,owner_epoch,route_version,state,reason,updated_at,pending_reconciliation FROM route_ownership ORDER BY spoke")
    def desired(self, site: str) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT site,version,digest,route_version,ownership_epoch,created_at,delivery_status,applied_status,verification_status FROM desired_states WHERE site=? ORDER BY version DESC", (site,))
    def policy_versions(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT version,digest,created_at,created_by FROM policy_versions ORDER BY version DESC")
    def destination_policy(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT v.version,v.digest,v.created_at,v.created_by,a.activated_at,a.activated_by FROM destination_policy_activation a JOIN destination_policy_versions v ON v.version=a.version")
    def desired_summary(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT site,MAX(version) AS latest_version,MAX(route_version) AS latest_route_version,MAX(created_at) AS last_created FROM desired_states GROUP BY site ORDER BY site")
    def ztp_devices(self) -> list[dict[str, Any]]:
        return self.state.rows("ztp", "SELECT device_id,assigned_site,status,public_key_fingerprint,created_at,updated_at FROM devices ORDER BY assigned_site")
    def events(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT actor,action,target,reason,result,before_version,after_version,created_at FROM policy_audit_events ORDER BY id DESC LIMIT 200")

    def runtime_view(self, site: str) -> dict[str, Any]:
        if site not in self.topology.site_names: return {"availability":"UNAVAILABLE", "reason":"unknown site"}
        return {"site":site,"links":self.runtime.links(site),"tunnels":self.runtime.tunnels(site),"routes":self.runtime.routes(site),"rules":self.runtime.rules(site),"failover":self.runtime.failover(site),"classifier":self.runtime.classifier(site)}
    def dashboard(self) -> dict[str, Any]:
        return {"health":self.health(),"topology":self.topology_view(),"sites":self.sites(),"desired":self.desired_summary(),"ownership":self.ownership(),"devices":self.ztp_devices(),"destination_policy":self.destination_policy()}

    def route_summary(self, site: str) -> dict[str, Any]:
        """Bounded evidence view: exclude local, broadcast, and IPv6 noise."""
        if site not in self.topology.site_names: return {"available":False,"reason":"unknown site"}
        routes=self.runtime.routes(site); rules=self.runtime.rules(site)
        if routes.get("availability") != "AVAILABLE": return {"available":False,"reason":routes.get("reason","runtime routes unavailable")}
        selected=[]
        for route in routes.get("value",[]):
            dev=str(route.get("dev", "")); table=str(route.get("table", "")); dst=str(route.get("dst", "default"))
            is_overlay=dev.startswith("wg-")
            is_direct=table in {str(item.route_table) for item in self.topology.transports.values()} and dev in {site + "-bb", site + "-lte"}
            if not table or not (is_overlay or is_direct): continue
            if ":" in dst or route.get("type") in ("local","broadcast","multicast"): continue
            bits=dev.split("-"); hub=("hub"+bits[1][1:]) if is_overlay and len(bits) >= 3 and bits[1].startswith("h") else None
            transport=bits[2] if is_overlay and len(bits) >= 3 else (dev.rsplit("-",1)[-1] if is_direct else None)
            selected.append({"destination":dst,"table":table,"fwmark_table":table,"next_hop":route.get("gateway"),"output_interface":dev,"hub":hub,"transport":transport,"egress_mode":"hub_overlay" if is_overlay else "direct_internet"})
        selected.sort(key=lambda item:(str(item["table"]),str(item["destination"])))
        grouped={}
        for route in selected:
            key=(route["table"], route["output_interface"])
            group=grouped.setdefault(key,{key:value for key,value in route.items() if key not in ("destination","protocol","scope")})
            group.setdefault("destinations",[]).append(route["destination"])
            if route.get("protocol") is not None: group["protocol"]=route["protocol"]
            if route.get("scope") is not None: group["scope"]=route["scope"]
        route_groups=list(grouped.values())[:64]
        policy_rules=[]
        if rules.get("availability") == "AVAILABLE":
            for rule in rules.get("value",[]):
                if rule.get("fwmark") is not None or str(rule.get("table","")).startswith(("11","12")):
                    policy_rules.append({key:rule.get(key) for key in ("priority","fwmark","fwmask","table","src","dst") if rule.get(key) is not None})
        return {"available":True,"site":site,"route_groups":route_groups,"routing_rules":policy_rules[:128],"return_affinity":{"configuration":"connmark-based; routes are selected by persistent connection mark and policy rule","evidence":"inspect the listed fwmark policy rules and selected WireGuard output interface"}}

    def compare_desired_actual(self, site: str) -> dict[str, Any]:
        """Compare only fields with compatible semantics; never ask the model to infer it."""
        if site not in self.topology.site_names:
            return {"available": False, "reason": "unknown site"}
        desired_rows = self.desired(site)
        runtime = self.runtime_view(site)
        latest = desired_rows[0] if desired_rows else None
        comparisons = []
        comparisons.append({"field": "desired_state_record", "desired_value": bool(latest), "observed_value": None, "comparison_status": "desired_only" if latest else "unavailable", "reason": "desired-state records and runtime namespace values are not the same semantic field"})
        runtime_available = all(isinstance(runtime.get(name), dict) and runtime[name].get("availability") == "AVAILABLE" for name in ("links", "routes", "rules", "tunnels") if name in runtime)
        comparisons.append({"field": "runtime_adapter", "desired_value": None, "observed_value": "AVAILABLE" if runtime_available else "UNAVAILABLE", "comparison_status": "observed_only", "reason": "runtime availability is observed independently of desired state"})
        return {"available": True, "site": site, "comparisons": comparisons, "desired_record": latest, "runtime_available": runtime_available,
                "limitations": ["No field is labeled match or mismatch unless desired and observed values have identical semantics."]}

    def route_decision_report(self, site: str, destination: str, source: str | None = None, fwmark: int | None = None) -> dict[str, Any]:
        """Perform a destination-aware read-only lookup without inventing fields."""
        import ipaddress
        if site not in self.topology.site_names:
            return {"available": False, "reason": "unknown site"}
        try:
            ipaddress.ip_address(destination)
            if source is not None:
                ipaddress.ip_address(source)
        except ValueError:
            return {"available": False, "reason": "invalid destination or source"}
        lookup = self.runtime.route_lookup(site, destination, source, fwmark)
        rules = self.runtime.rules(site)
        if lookup.get("availability") != "AVAILABLE":
            return {"available": False, "reason": lookup.get("reason", "runtime route lookup unavailable")}
        values = lookup.get("value", [])
        selected = values[0] if isinstance(values, list) and values else {}
        matched_rule = None
        if fwmark is not None and rules.get("availability") == "AVAILABLE":
            for rule in rules.get("value", []):
                try:
                    mark = int(str(rule.get("fwmark", "-1")), 0)
                    mask = int(str(rule.get("fwmask", "0xffffffff")), 0)
                    if fwmark & mask == mark & mask:
                        candidate = {"priority": rule.get("priority"), "table": rule.get("table"), "fwmark": rule.get("fwmark"), "fwmask": rule.get("fwmask")}
                        if matched_rule is None or int(candidate["priority"] or 2**31) < int(matched_rule["priority"] or 2**31):
                            matched_rule = candidate
                except (TypeError, ValueError):
                    continue
        dev = selected.get("dev")
        derived = {"hub": None, "transport": None}
        if isinstance(dev, str) and dev.startswith("wg-"):
            parts = dev.split("-")
            if len(parts) >= 3 and parts[1].startswith("h"):
                derived["hub"] = "hub" + parts[1][1:]
                derived["transport"] = parts[2]
        unknowns = []
        if fwmark is None:
            unknowns.append({"field": "matched_rule", "reason": "no packet fwmark was supplied"})
        if not selected:
            unknowns.append({"field": "matched_route", "reason": "runtime lookup returned no route record"})
        for field, value in (("selected_routing_table", selected.get("table")), ("next_hop", selected.get("gateway")), ("output_interface", dev), ("connection_mark", None)):
            if value is None:
                unknowns.append({"field": field, "reason": "not reported by the current routing adapter"})
        return {"available": True, "site": site, "destination": destination, "source": source, "packet_mark": fwmark,
                "matched_rule": matched_rule, "selected_routing_table": selected.get("table"),
                "matched_route": {key: selected.get(key) for key in ("dst", "gateway", "dev", "prefsrc", "type") if selected.get(key) is not None} or None,
                "next_hop": selected.get("gateway"), "output_interface": dev,
                "connection_mark": None, "derived": derived,
                "state_kind": {"packet_mark": "observed" if fwmark is not None else "unavailable", "matched_rule": "derived" if matched_rule else "unavailable", "matched_route": "observed" if selected else "unavailable", "hub": "derived" if derived["hub"] else "unavailable", "transport": "derived" if derived["transport"] else "unavailable"},
                "unknowns": unknowns,
                "limitations": ["The route lookup reflects the supplied destination, optional source, and optional fwmark only.", "A connection mark is not exposed by the current routing adapter."],
                "warnings": []}

    def hub_view(self, hub: str) -> dict[str, Any]:
        if hub not in self.topology.hubs: return {"availability":"UNAVAILABLE", "reason":"unknown hub"}
        return {"hub":hub,"configured":{"management_ip":str(self.topology.hubs[hub].management_ip)},"runtime":self.runtime_view(hub)}
    def network_view(self, kind: str) -> dict[str, Any]:
        c=self.topology
        if kind == "data-center": return {"network":str(c.data_center_network),"endpoint":str(c.data_center_app_ip),"name":c.data_center_app_name,"return_affinity":"hub scoped SNAT plus connmark"}
        if kind == "saas": return {"network":str(c.saas_network),"endpoint":str(c.saas_ip),"name":c.saas_app_name,"egress":"policy controlled direct internet or hub backhaul"}
        if kind == "cloud-vpc": return {"enabled":c.cloud_vpc.enabled,"network":str(c.cloud_vpc.network),"endpoint":str(c.cloud_vpc.app_ip),"gateways":list(c.cloud_vpc.active_gateways),"availability":"CONFIGURED" if c.cloud_vpc.enabled else "DISABLED"}
        return {"availability":"UNAVAILABLE", "reason":"unknown network view"}

    def topology_nodes(self) -> list[dict[str, Any]]:
        plan=build_live_plan(self.topology)
        return ([{"name":item.name,"kind":"switch","openflow":item.openflow,"dpid":item.dpid} for item in plan.switches] + [{"name":item.name,"kind":"docker","role":item.role,"image":item.image} for item in plan.docker_nodes])
    def topology_links(self) -> list[dict[str, Any]]:
        return [{"node1":item.node1,"node2":item.node2,"interface1":item.intf1,"interface2":item.intf2,"address1":item.address1,"address2":item.address2,"transport":item.transport} for item in build_live_plan(self.topology).links]
    def combined_events(self) -> list[dict[str, Any]]:
        return self.events()+[{"source":"management","event":item} for item in self.audit.list()]
