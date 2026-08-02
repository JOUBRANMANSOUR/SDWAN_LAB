"""Shared read-only query layer used by REST, MCP, and the Agent Gateway."""
from __future__ import annotations
from typing import Any
from ..common.model import load_config
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
    def ztp_devices(self) -> list[dict[str, Any]]:
        return self.state.rows("ztp", "SELECT device_id,assigned_site,status,public_key_fingerprint,created_at,updated_at FROM devices ORDER BY assigned_site")
    def events(self) -> list[dict[str, Any]]:
        return self.state.rows("policy", "SELECT actor,action,target,reason,result,before_version,after_version,created_at FROM policy_audit_events ORDER BY id DESC LIMIT 200")

    def runtime_view(self, site: str) -> dict[str, Any]:
        if site not in self.topology.site_names: return {"availability":"UNAVAILABLE", "reason":"unknown site"}
        return {"site":site,"links":self.runtime.links(site),"tunnels":self.runtime.tunnels(site),"routes":self.runtime.routes(site),"rules":self.runtime.rules(site),"failover":self.runtime.failover(site),"classifier":self.runtime.classifier(site)}
    def dashboard(self) -> dict[str, Any]:
        return {"health":self.health(),"topology":self.topology_view(),"sites":self.sites(),"ownership":self.ownership(),"devices":self.ztp_devices()}

    def chat(self, actor: str, session: int, prompt: str) -> dict[str, Any]:
        self.audit.add_message(session, actor, prompt)
        reply = "Read-only diagnosis: " + ("runtime adapter is available for configured nodes." if self.config.agent_command else "external Agent Gateway is disabled; use dashboard, site runtime, and events endpoints.")
        self.audit.add_message(session, "management", reply)
        self.audit.add(actor, "CHAT", str(session), "ok", "read-only summary")
        return {"session_id":session,"reply":reply,"agent_gateway":"CONFIGURED_NOT_EXECUTED" if self.config.agent_command else "DISABLED","evidence":{"health":self.health(),"ownership":self.ownership()}}
