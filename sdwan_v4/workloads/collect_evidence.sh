#!/bin/sh
set -eu
site="${1:?usage: collect_evidence.sh SITE SERVER_IP [SECONDS] [OUTPUT_DIR]}"
server="${2:?server IP required}"
seconds="${3:-15}"
output="${4:-/tmp/sdwan-v4-evidence}"
mkdir -p "$output"
cleanup() { jobs -p | xargs -r kill 2>/dev/null || true; }
trap cleanup EXIT INT TERM
timeout "$seconds" tcpdump -U -n -i "${site}-lan" -c 300 -w "$output/${site}-lan.pcap" "host $server" &
timeout "$seconds" tcpdump -U -n -i "${site}-mpls" -c 300 -w "$output/${site}-mpls.pcap" 'udp port 51820' &
timeout "$seconds" tcpdump -U -n -i "${site}-bb" -c 300 -w "$output/${site}-bb.pcap" 'udp port 51821' &
timeout "$seconds" tcpdump -U -n -i "${site}-lte" -c 300 -w "$output/${site}-lte.pcap" 'udp port 51822' &
timeout "$seconds" tcpdump -U -n -i wg-mpls -c 300 -w "$output/wg-mpls.pcap" "host $server" &
timeout "$seconds" tcpdump -U -n -i wg-bb -c 300 -w "$output/wg-bb.pcap" "host $server" &
timeout "$seconds" tcpdump -U -n -i wg-lte -c 300 -w "$output/wg-lte.pcap" "host $server" &
wait || true
iptables-save -t mangle >"$output/iptables-mangle.txt"
ip rule show >"$output/ip-rules.txt"
for table in 101 102 103; do ip route show table "$table" >"$output/routes-$table.txt"; done
conntrack -L -o extended >"$output/conntrack.txt" 2>&1 || true
wg show all dump >"$output/wireguard.txt"
tc -s qdisc show >"$output/qdisc.txt"
cat /proc/net/netfilter/nfnetlink_queue >"$output/nfqueue.txt" 2>/dev/null || true
nstat -az >"$output/nstat.txt" 2>/dev/null || true
ps -eo pid,ppid,pcpu,pmem,rss,vsz,comm,args >"$output/processes.txt"
echo "bounded evidence saved in $output"

