#!/bin/sh
set -eu
project="$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)"
python_bin="${VALIDATION_PYTHON:-python3}"
cd "$project"
"$python_bin" -m compileall -q sdwan_v4
"$python_bin" -m sdwan_v4.config_loader_v4
"$python_bin" -m pytest -q sdwan_v4/tests -m 'not live'
if "$python_bin" -m ruff --version >/dev/null 2>&1; then "$python_bin" -m ruff check sdwan_v4; fi
for script in sdwan_v4/scripts/*.sh sdwan_v4/workloads/*.sh sdwan_v4/nginx/*.sh; do sh -n "$script"; done
if grep -RIl "$(printf '\r')" sdwan_v4/scripts sdwan_v4/workloads sdwan_v4/nginx | grep .; then
  echo 'CRLF found in executable artifact' >&2; exit 1
fi
echo 'static validation passed'
