"""sdwan-management-mcp: local stdio JSON-RPC server; no TCP/HTTP listener."""
from __future__ import annotations
import json, os, sys
from typing import Any, Dict
from sdwan_v5.management.auth import allowed, verify_agent_context
from sdwan_v5.management.config import ManagementConfig
from sdwan_v5.management.service import ManagementService
TOOLS = {"get_dashboard_summary": ("network:read", lambda s,a: s.dashboard()), "list_sites": ("network:read", lambda s,a: s.sites()), "get_site_status": ("network:read", lambda s,a: s.runtime_view(a["site"])), "get_site_tunnels": ("network:read", lambda s,a: s.runtime_view(a["site"]).get("tunnels")), "get_site_routes": ("network:read", lambda s,a: s.runtime_view(a["site"]).get("routes")), "get_topology": ("network:read", lambda s,a: s.topology_view()), "get_hub_status": ("network:read", lambda s,a: s.hub_view(a["hub"])), "get_cloud_status": ("network:read", lambda s,a: s.network_view("cloud-vpc")), "get_saas_status": ("network:read", lambda s,a: s.network_view("saas")), "compare_desired_actual": ("network:read", lambda s,a: {"desired":s.desired(a["site"]), "actual":s.runtime_view(a["site"])}), "explain_route_decision": ("network:read", lambda s,a: {"site":a["site"], "routes":s.runtime_view(a["site"]).get("routes"), "ownership":s.ownership()}), "get_recent_events": ("audit:read", lambda s,a: s.combined_events())}
def response(i, result=None, error=None):
    out={"jsonrpc":"2.0","id":i}
    if error: out["error"]={"code":-32001,"message":error}
    else: out["result"]=result
    sys.stdout.write(json.dumps(out,separators=(",",":"))+"\n"); sys.stdout.flush()
def main():
    config=ManagementConfig.from_env(); sid=os.environ.get("SDWAN_CHAT_SESSION_ID", ""); token=os.environ.get("SDWAN_AGENT_CONTEXT_TOKEN", "")
    try: principal=verify_agent_context(config.signing_secret, token, sid, os.environ.get("SDWAN_AGENT_CONTEXT_AUDIENCE", config.agent_context_audience), config.agent_context_ttl_seconds)
    except ValueError: return 2
    service=ManagementService(config)
    for line in sys.stdin:
        try: request=json.loads(line); method=request.get("method"); ident=request.get("id")
        except json.JSONDecodeError: continue
        if method=="initialize": response(ident,{"protocolVersion":"2024-11-05","serverInfo":{"name":"sdwan-management-mcp","version":"1.0.0"},"capabilities":{"tools":{}}})
        elif method=="tools/list": response(ident,{"tools":[{"name":name,"description":"Read-only SD-WAN query","inputSchema":{"type":"object","properties":{"site":{"type":"string"},"hub":{"type":"string"}}}} for name in sorted(TOOLS)]})
        elif method=="tools/call":
            params=request.get("params", {}); name=str(params.get("name", "")); args=params.get("arguments", {})
            if name not in TOOLS: response(ident,error="unknown read-only tool"); continue
            scope, fn=TOOLS[name]
            if not allowed(principal, "mcp:read") or not allowed(principal, scope): response(ident,error="permission denied"); continue
            try:
                value=fn(service, args if isinstance(args,dict) else {}); text=json.dumps(value,default=str)[:32768]; service.audit.add(principal.subject,"MCP_TOOL",name,"200",json.dumps(args)[:256]); response(ident,{"content":[{"type":"text","text":text}]})
            except Exception: response(ident,error="read-only tool unavailable")
        elif method=="notifications/initialized": pass
        else: response(ident,error="unsupported MCP method")
    return 0
if __name__ == "__main__": raise SystemExit(main())
