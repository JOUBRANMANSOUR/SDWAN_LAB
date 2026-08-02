# Management REST API

All fabric endpoints are read-only: `/api/v1/system/health`, `/api/v1/system/capabilities`, `/api/v1/topology`, `/api/v1/sites`, `/api/v1/sites/{site}/desired`, `/api/v1/routes/ownership`, `/api/v1/ztp/devices`, `/api/v1/events`, `/api/v1/audit`, and `/api/v1/events/stream` (SSE). Authentication is local lab bearer authentication through `POST /api/v1/auth/login`.
