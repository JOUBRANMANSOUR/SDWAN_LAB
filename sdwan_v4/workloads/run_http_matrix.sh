#!/bin/sh
set -eu
url="${1:?usage: run_http_matrix.sh URL [OUTPUT_DIR]}"
output="${2:-/tmp/sdwan-v4-http-matrix}"
base="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
mkdir -p "$output"
for clients in 1 2 3 10; do
  python3 "$base/http_load.py" "$url" --clients "$clients" \
    --prefix "http-${clients}" >"$output/http-${clients}.json"
done
echo "$output"
