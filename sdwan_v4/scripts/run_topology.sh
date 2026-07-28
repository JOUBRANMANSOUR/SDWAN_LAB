#!/bin/sh
set -eu
project="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
: "${CONTAINERNET_VENV:?set CONTAINERNET_VENV to the existing working Containernet environment}"
exec sudo --preserve-env=SDWAN_SHARED_TOKEN,PYTHONPATH \
  env PYTHONPATH="$project${PYTHONPATH:+:$PYTHONPATH}" \
  "$CONTAINERNET_VENV/bin/python" -m sdwan_v4.topology_v4 \
  --config-dir "$project/sdwan_v4/config"
