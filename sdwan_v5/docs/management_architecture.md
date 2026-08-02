# Management platform

Run with the existing Ryu environment:

```bash
source ~/ryu-venv38/bin/activate
cd /mnt/data/sdwan-lab
set -a; source sdwan_v5/.env.example; set +a
export SDWAN_MANAGEMENT_SECRET="replace-this"
PYTHONPATH=$PWD python -m sdwan_v5.management.main
```

Use `POST /api/v1/auth/login`, then send its bearer token to read-only `/api/v1` endpoints. Roles: VIEWER (topology/health), NETWORK_ADMIN (routes/tunnels/events), AUDITOR (audit/events), PLATFORM_ADMIN (all reads/chat). `/mcp` exposes only read-only tools. Runtime availability is reported honestly; no REST/MCP endpoint changes fabric state.
