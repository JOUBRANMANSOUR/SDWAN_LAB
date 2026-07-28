#!/bin/sh
set -eu
project="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
: "${CONTAINERNET_VENV:?set CONTAINERNET_VENV to the working Containernet environment}"
cd "$project"
sudo --preserve-env=SDWAN_SHARED_TOKEN,PYTHONPATH \
  env PYTHONPATH="$project${PYTHONPATH:+:$PYTHONPATH}" SDWAN_RUN_LIVE=1 \
  "$CONTAINERNET_VENV/bin/python" -m pytest -v -m live sdwan_v4/tests/test_live_lab.py
exec sudo --preserve-env=SDWAN_SHARED_TOKEN,PYTHONPATH \
  env PYTHONPATH="$project${PYTHONPATH:+:$PYTHONPATH}" \
  "$CONTAINERNET_VENV/bin/python" -m sdwan_v4.topology_v4 \
  --config-dir "$project/sdwan_v4/config" --no-cli --smoke-protocols
