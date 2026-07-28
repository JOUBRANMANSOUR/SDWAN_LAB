#!/bin/sh
set -eu
server="${1:-10.2.0.11}"
base="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
echo 'Generic TCP requires tcp_test.py server on port 9000'
python3 "$base/tcp_test.py" client "$server" --flow-id matrix-tcp
echo 'Pure UDP requires udp_test.py server on port 9999'
python3 "$base/udp_test.py" client "$server" --flow-id matrix-udp
dig @"$server" sdwan-lab.local A +time=1 +tries=1 || true
for fixture in sip stun rtp udp443-nonquic; do
  python3 "$base/protocol_fixtures.py" "$fixture" "$server"
done
python3 "$base/quic_test.py" client "$server"
curl --fail --output /dev/null "http://$server/healthz"
curl --fail --insecure --output /dev/null "https://$server/healthz"
curl --fail --output /dev/null "ftp://$server/sdwan-200M.bin" || true
ssh -i /opt/sdwan-lab-ssh/id_ed25519 -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null sdwan@"$server" true

