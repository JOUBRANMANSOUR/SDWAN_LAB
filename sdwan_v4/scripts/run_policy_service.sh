#!/bin/sh
set -eu
project="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
: "${RYU_VENV:?set RYU_VENV to the existing working Ryu virtual environment}"
export PYTHONPATH="$project${PYTHONPATH:+:$PYTHONPATH}"
exec "$RYU_VENV/bin/python" -m sdwan_v4.policy_service_v4 --host 0.0.0.0 --port 8080
