#!/bin/sh
set -eu
project="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
docker build -f "$project/docker/Dockerfile.edge.v4" -t containernet-sdwan-edge-v4:latest "$project"
docker build -f "$project/docker/Dockerfile.host.v4" -t containernet-sdwan-host-v4:latest "$project"
