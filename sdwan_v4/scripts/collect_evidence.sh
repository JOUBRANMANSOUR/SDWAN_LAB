#!/bin/sh
set -eu
output="${1:-evidence/v4-$(date -u +%Y%m%dT%H%M%SZ)}"
mkdir -p "$output"
ip rule show >"$output/ip-rule.txt"
ip route show table all >"$output/ip-route-all.txt"
iptables-save -t mangle >"$output/iptables-mangle.txt"
conntrack -L -o extended >"$output/conntrack.txt" 2>&1 || true
wg show all dump >"$output/wireguard.txt"
cat /proc/net/netfilter/nfnetlink_queue >"$output/nfqueue.txt" 2>/dev/null || true
echo "$output"
