#!/bin/sh
set -eu
project="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
: "${RYU_VENV:?set RYU_VENV to the existing working Ryu virtual environment}"
export PYTHONPATH="$project${PYTHONPATH:+:$PYTHONPATH}"
exec "$RYU_VENV/bin/ryu-manager" --ofp-tcp-listen-port 6633 sdwan_v4.controller_v4
