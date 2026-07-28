# Ubuntu 24.04 runbook

Replace `/home/lab/sdwan-lab`, `/opt/venvs/ryu`, and `/opt/venvs/containernet` below with your real paths. Do not create new environments if your existing ones work.

## 1. Copy from Windows

Copy the complete directory:

```text
D:\999999999\PROJECT\PROJECT Codes\files\sdwan_v4
```

Place it as:

```text
/home/lab/sdwan-lab/sdwan_v4
```

Example from Windows PowerShell (replace the SSH user/host and Ubuntu parent path):

```powershell
scp -r "D:\999999999\PROJECT\PROJECT Codes\files\sdwan_v4" labuser@ubuntu-host:/home/lab/sdwan-lab/
```

With WinSCP, drag only the `sdwan_v4` folder into `/home/lab/sdwan-lab/`.

Copy no parent metadata. Do not copy `.git`, `.agents`, `.codex`, `.ruff_cache`, `.pytest_cache`, `__pycache__`, `*.pyc`, Windows virtual environments, build directories, temporary nDPI downloads, or pcaps unless intentionally archiving evidence. The delivered v4 directory is cleaned of Python caches.

On Ubuntu:

```bash
cd /home/lab/sdwan-lab
find sdwan_v4 -type f -name '*.sh' -exec chmod 0755 {} +
python3 - <<'PY'
from pathlib import Path
bad = [p for p in Path('sdwan_v4').rglob('*') if p.is_file() and b'\r\n' in p.read_bytes()]
if bad:
    raise SystemExit(f'CRLF files: {bad}')
print('LF check passed')
PY
```

## 2. Install role-specific Python packages

Ryu environment—runs Ryu and the policy service:

```bash
source /opt/venvs/ryu/bin/activate
python -m pip install -r /home/lab/sdwan-lab/sdwan_v4/requirements-controller.txt
deactivate
```

Containernet environment—runs topology, orchestration, and live tests:

```bash
source /opt/venvs/containernet/bin/activate
python -m pip install -r /home/lab/sdwan-lab/sdwan_v4/requirements-topology.txt
deactivate
```

The edge Python environment is built inside the edge image from `requirements-edge.txt`. The native classifier and nDPI do not run in either host Python environment.

## 3. Static validation

```bash
cd /home/lab/sdwan-lab
source /opt/venvs/containernet/bin/activate
python -m pip install -r sdwan_v4/requirements-dev.txt
VALIDATION_PYTHON="$VIRTUAL_ENV/bin/python" ./sdwan_v4/scripts/validate_static.sh
deactivate
```

This does not validate Linux packet steering.

## 4. Build Docker images

```bash
cd /home/lab/sdwan-lab
./sdwan_v4/scripts/build_images.sh
docker image inspect containernet-sdwan-edge-v4:latest >/dev/null
docker image inspect containernet-sdwan-host-v4:latest >/dev/null
```

The edge multi-stage build clones nDPI tag `5.0`, rejects any commit other than `375f99ef9fb4999d778b57bbeece171b3fa9fba6`, builds the native classifier, and leaves compilers out of the runtime image.

## 5. Startup order

Choose one shared token for all three terminals:

```bash
export SDWAN_SHARED_TOKEN='replace-with-a-long-lab-secret'
```

Terminal 1—policy service in the Ryu environment:

```bash
cd /home/lab/sdwan-lab
export RYU_VENV=/opt/venvs/ryu
export SDWAN_SHARED_TOKEN='replace-with-a-long-lab-secret'
./sdwan_v4/scripts/run_policy_service.sh
```

It binds `0.0.0.0:8080`; the topology later creates host interface `172.30.0.254/24`.

Terminal 2—Ryu in the Ryu environment:

```bash
cd /home/lab/sdwan-lab
export RYU_VENV=/opt/venvs/ryu
export SDWAN_SHARED_TOKEN='replace-with-a-long-lab-secret'
./sdwan_v4/scripts/run_controller.sh
```

Terminal 3—topology in the Containernet environment:

```bash
cd /home/lab/sdwan-lab
export CONTAINERNET_VENV=/opt/venvs/containernet
export SDWAN_SHARED_TOKEN='replace-with-a-long-lab-secret'
./sdwan_v4/scripts/run_topology.sh
```

The topology starts `edge_agent_v4.py` inside all seven edge containers. Each spoke edge supervises `/usr/local/sbin/sdwan-classifier-v4`; hubs do not perform competing LAN-origin DPI.

## 6. Traffic in the topology CLI

Start realistic services on `node2-h1` and generic echo servers:

```text
node2-h1 sh /opt/sdwan_v4/workloads/start_test_services.sh 200
node2-h1 python3 /opt/sdwan_v4/workloads/tcp_test.py server --bind 10.2.0.11 &
node2-h1 python3 /opt/sdwan_v4/workloads/udp_test.py server --bind 10.2.0.11 &
```

Generate flows:

```text
node1-h1 python3 /opt/sdwan_v4/workloads/tcp_test.py client 10.2.0.11 --flow-id tcp-1
node1-h1 python3 /opt/sdwan_v4/workloads/udp_test.py client 10.2.0.11 --flow-id udp-1
node1-h1 curl --fail --output /dev/null http://10.2.0.11/sdwan-200M.bin
node1-h1 curl --fail --insecure --output /dev/null https://10.2.0.11/healthz
node1-h1 dig @10.2.0.11 sdwan-lab.local A
node1-h1 python3 /opt/sdwan_v4/workloads/quic_test.py client 10.2.0.11
node1-h1 ssh -i /opt/sdwan-lab-ssh/id_ed25519 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null sdwan@10.2.0.11 true
node1-h1 curl --fail --output /dev/null ftp://10.2.0.11/sdwan-200M.bin
```

The `udp443-nonquic` fixture is a negative port-hint test; only `quic_test.py` is real QUIC.

Multi-flow Nginx experiment (1, 2, 3, then 10 concurrent downloads):

```text
node1-h1 python3 /opt/sdwan_v4/workloads/http_load.py http://10.2.0.11/sdwan-200M.bin --clients 1 --prefix http-1
node1-h1 python3 /opt/sdwan_v4/workloads/http_load.py http://10.2.0.11/sdwan-200M.bin --clients 2 --prefix http-2
node1-h1 python3 /opt/sdwan_v4/workloads/http_load.py http://10.2.0.11/sdwan-200M.bin --clients 3 --prefix http-3
node1-h1 python3 /opt/sdwan_v4/workloads/http_load.py http://10.2.0.11/sdwan-200M.bin --clients 10 --prefix http-10
```

Or run the complete matrix into JSON files:

```text
node1-h1 sh /opt/sdwan_v4/workloads/run_http_matrix.sh http://10.2.0.11/sdwan-200M.bin /tmp/http-matrix
```

More clients do not directly select a new path. A new-flow change occurs only after measured degradation, complete epochs, hysteresis, hold-down, and improvement requirements.

## 7. Observe, degrade, and fail

```text
showclassifications node1
showflows node1
showqueues node1
degrade node1 bb 150 5 30
saturate node1 bb 45M
linkdown node1 bb
linkup node1 bb
restore node1 bb
```

Classifier recovery test:

```text
node1 pkill -TERM -x sdwan-classifier-v4
node1 pgrep -a sdwan-classifier-v4
```

Confirm restart counters through `showqueues node1` or the edge state endpoint. Do not flush conntrack during this test.

Policy-service and Ryu outage tests are performed by stopping their respective terminal processes while existing traffic continues, then restarting them. Record behavior before, during, and after expiry/reconciliation.

Transactional hub-failover experiment from the Ubuntu host:

```bash
curl --fail -X POST http://172.30.0.254:8080/sdwan/failover \
  -H "X-SDWAN-Token: $SDWAN_SHARED_TOKEN" -H 'Content-Type: application/json' \
  -d '{"spoke":"node1","new_hub":"hub2"}'
```

The service applies hub/peer state, verifies all three overlays, and attempts rollback on failure. Because phase 1 has one interface per path, this is not fully make-before-break.

## 8. tcpdump and correlated evidence

Use tcpdump only for validation/troubleshooting:

```text
node1 tcpdump -ni node1-lan -c 50
node1 tcpdump -ni wg-bb -c 50
node1 tcpdump -ni node1-bb udp port 51821 -c 50
```

Expected boundary: LAN and WireGuard interfaces expose inner traffic; the underlay exposes encrypted WireGuard UDP. Correlate this with:

```text
showclassifications node1
showflows node1
node1 ip rule show
node1 ip route show table 101
node1 ip route show table 102
node1 ip route show table 103
node1 wg show
```

## 9. Automated Ubuntu gate

Keep policy service and Ryu running, then execute in a fourth terminal:

```bash
cd /home/lab/sdwan-lab
export CONTAINERNET_VENV=/opt/venvs/containernet
export SDWAN_SHARED_TOKEN='replace-with-a-long-lab-secret'
./sdwan_v4/scripts/validate_live.sh
```

It performs prerequisite tests, starts an isolated no-CLI topology, validates datapaths/NFQUEUE/rules/WireGuard/intersite forwarding, runs protocol smoke tests, and cleans up.

## 10. Shutdown and cleanup

Exit the topology CLI, stop Ryu and policy service with Ctrl-C, then:

```bash
sudo mn -c
docker ps --format '{{.Names}}' | grep -E '(^|[._-])(hub[12]|node[1-5])([._-]|$)' || true
```

Do not remove v3 files or images. Preserve evidence directories separately before cleanup.

## Troubleshooting

- Policy service cannot bind: v4 must use `0.0.0.0:8080`; check for another process on 8080.
- Datapaths missing: confirm Ryu listens on 6633 and policy receives `/sdwan/openflow-state`.
- Classifier unhealthy: inspect the edge process output, `pgrep`, `/proc/net/netfilter/nfnetlink_queue`, and nDPI runtime revision.
- No route selection: inspect mangle rules, conntrack mark, `ip rule`, table 101/102/103, then WireGuard counters—in that order.
- No classification: capture plaintext at LAN/WG, not encrypted underlay; check flow state/reason/native confidence rather than ports.
- Queue overload: compare `ENOBUFS`, truncation, event drops, kernel queue state, CPU, and the explicit provisional mark. Queue-bypass and queue-full fail-open are different tests.
