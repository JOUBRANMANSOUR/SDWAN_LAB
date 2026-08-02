"""FastAPI read-only management REST API and minimal SSE/UI surface."""
from __future__ import annotations
import asyncio, json
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel
from .auth import Principal, allowed, issue, parse_users, scopes_for, verify
from .config import ManagementConfig
from .service import ManagementService
from ..sdwan_mcp.app import install_mcp

class Login(BaseModel): username: str; password: str
def create_app(config: ManagementConfig | None = None) -> FastAPI:
    config=config or ManagementConfig.from_env(); service=ManagementService(config); app=FastAPI(title="SD-WAN v5 Management", version="1.0.0")
    bearer = HTTPBearer(auto_error=False)
    def principal(credentials: HTTPAuthorizationCredentials = Depends(bearer)) -> Principal:
        if credentials is None:
            raise HTTPException(401, "authentication required")
        try: return verify(config.signing_secret, credentials.credentials)
        except Exception: raise HTTPException(401, "authentication required")
    def require(scope: str):
        def check(user: Principal = Depends(principal)) -> Principal:
            if not allowed(user,scope): raise HTTPException(403,"scope denied")
            return user
        return check
    @app.post("/api/v1/auth/login")
    def login(value: Login):
        record=parse_users(config.users).get(value.username)
        if record is None or record[0] != value.password: raise HTTPException(401,"invalid credentials")
        user=Principal(value.username,record[1],scopes_for(record[1])); service.audit.add(user.subject,"LOGIN","session","ok")
        return {"access_token":issue(config.signing_secret,user),"token_type":"bearer","role":user.role,"scopes":user.scopes}
    @app.get("/api/v1/system/health")
    def health(user: Principal = Depends(require("read:health"))): return service.health()
    @app.get("/api/v1/system/capabilities")
    def capabilities(user: Principal = Depends(require("read:health"))): return {"read_only":True,"rest":True,"mcp":"/mcp","agent_gateway":bool(config.agent_command),"unsupported":["policy writes","ztp writes","routing writes","docker exec from browser"]}
    @app.get("/api/v1/dashboard")
    def dashboard(user: Principal = Depends(require("read:operations"))): return service.dashboard()
    @app.get("/api/v1/topology")
    def topology(user: Principal = Depends(require("read:topology"))): return service.topology_view()
    @app.get("/api/v1/sites")
    def sites(user: Principal = Depends(require("read:operations"))): return service.sites()
    @app.get("/api/v1/sites/{site}/desired")
    def desired(site: str,user: Principal = Depends(require("read:operations"))): return service.desired(site)
    @app.get("/api/v1/sites/{site}/runtime")
    def runtime(site: str,user: Principal = Depends(require("read:tunnels"))): return service.runtime_view(site)
    @app.get("/api/v1/routes/ownership")
    def ownership(user: Principal = Depends(require("read:routes"))): return service.ownership()
    @app.get("/api/v1/ztp/devices")
    def devices(user: Principal = Depends(require("read:operations"))): return service.ztp_devices()
    @app.get("/api/v1/events")
    def events(user: Principal = Depends(require("read:events"))): return service.events()
    @app.get("/api/v1/audit")
    def audit(user: Principal = Depends(require("read:audit"))): return service.audit.list()
    @app.get("/api/v1/events/stream")
    async def stream(user: Principal = Depends(require("read:events"))):
        async def generate():
            yield "event: snapshot\ndata: " + json.dumps(service.events()) + "\n\n"
        return StreamingResponse(generate(),media_type="text/event-stream")
    @app.get("/", response_class=HTMLResponse)
    def ui(): return "<html><body><h1>SD-WAN v5 Management</h1><p>Read-only laboratory console. Authenticate with /api/v1/auth/login, then query /api/v1/system/health.</p></body></html>"
    install_mcp(app, service, principal)
    return app
