#!/usr/bin/env python3
"""Containernet topology and site-scoped SD-WAN v4 laboratory CLI."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from typing import Any

import requests

from .command_v4 import NodeCommandRunner
from .config_loader_v4 import CONFIG_DIR, PolicyBundle, load_bundle


PROJECT_DIR = Path(__file__).resolve().parent


class SDWANLab:
    def __init__(self, bundle: PolicyBundle):
        self.bundle = bundle
        self.config = bundle.topology
        self.net: Any | None = None
        self.routers: dict[str, Any] = {}
        self.hosts: dict[str, Any] = {}
        self.switches: dict[str, Any] = {}
        self.agents: dict[str, Any] = {}
        self.load_processes: list[Any] = []
        self.public_keys: dict[str, str] = {}
        self.runtime_dir = Path(tempfile.mkdtemp(prefix="sdwan-v4-keys-"))
        self.runtime_dir.chmod(0o700)
        for site in self.config.site_names:
            (self.runtime_dir / site).mkdir(mode=0o700)

    @property
    def token(self) -> str:
        return os.getenv(self.config.controller.shared_token_env, "")

    @property
    def headers(self) -> dict[str, str]:
        return {"X-SDWAN-Token": self.token} if self.token else {}

    @property
    def controller_url(self) -> str:
        address = self.config.controller.management_address.split("/", 1)[0]
        return f"http://{address}:{self.config.controller.policy_port}"

    def edge_url(self, site: str, path: str = "/sdwan/state") -> str:
        return f"http://{self.config.management_ip(site)}:{self.config.controller.edge_port}{path}"

    def build(self) -> None:
        try:
            from mininet.link import TCLink
            from mininet.net import Containernet
            from mininet.node import Node, RemoteController
            from mininet.nodelib import LinuxBridge
        except ImportError as exc:
            raise RuntimeError("run topology_v4 from the working Ubuntu Containernet environment") from exc
        net = Containernet(controller=None, link=TCLink)
        self.net = net
        net.addController(
            "c0", controller=RemoteController, ip=self.config.controller.openflow_host,
            port=self.config.controller.openflow_port,
        )
        for underlay in self.config.underlays.values():
            self.switches[underlay.switch] = net.addSwitch(
                underlay.switch, dpid=f"{underlay.dpid:016x}", protocols="OpenFlow13",
            )
        management = net.addSwitch("mgmtbr", cls=LinuxBridge, stp=False)
        source_mount = f"{PROJECT_DIR}:/opt/sdwan_v4:ro"
        project_mount = f"{PROJECT_DIR.parent}:/opt/project:ro"
        environment = {"PYTHONPATH": "/opt/project"}
        if self.token:
            environment[self.config.controller.shared_token_env] = self.token
        for site in self.config.site_names:
            key_mount = f"{self.runtime_dir / site}:/run/sdwan-keys:rw"
            router = net.addDocker(
                site, dimage=self.config.edge_image, cap_add=["NET_ADMIN", "NET_RAW"],
                volumes=[source_mount, project_mount, key_mount], environment=environment,
            )
            self.routers[site] = router
            net.addLink(router, management, intfName1=f"{site}-mgmt")
        root = net.addHost("mgmtroot", cls=Node, inNamespace=False)
        net.addLink(root, management, intfName1="mgmtroot-eth0")
        self.routers["mgmtroot"] = root
        for site in self.config.site_names:
            for path, underlay in self.config.underlays.items():
                net.addLink(
                    self.routers[site], self.switches[underlay.switch], cls=TCLink,
                    intfName1=f"{site}-{path}", intfName2=f"{underlay.switch}-{site}",
                    bw=underlay.bandwidth_mbps, delay=f"{underlay.delay_ms}ms",
                    jitter=f"{underlay.jitter_ms}ms", loss=underlay.loss_pct,
                )
        for spoke in self.config.spokes.values():
            lan = net.addSwitch(
                spoke.lan_switch, dpid=f"{spoke.lan_dpid:016x}", protocols="OpenFlow13",
            )
            self.switches[spoke.lan_switch] = lan
            net.addLink(self.routers[spoke.name], lan, intfName1=f"{spoke.name}-lan")
            for number in (1, 2, 3):
                name = f"{spoke.name}-h{number}"
                host = net.addDocker(
                    name, dimage=self.config.host_image,
                    volumes=[source_mount, project_mount], environment={"PYTHONPATH": "/opt/project"},
                )
                self.hosts[name] = host
                net.addLink(host, lan)
        net.start()
        self._addresses()
        self._keys()
        self._agents()
        self._register()
        self.verify()

    @staticmethod
    def _address(runner: NodeCommandRunner, interface: str, cidr: str) -> None:
        runner.run(f"ip address flush dev {interface}", f"flush {interface}")
        runner.run(f"ip address add {cidr} dev {interface}", f"address {interface}")
        runner.run(f"ip link set dev {interface} up", f"enable {interface}")

    def _addresses(self) -> None:
        self._address(
            NodeCommandRunner(self.routers["mgmtroot"]), "mgmtroot-eth0",
            self.config.controller.management_address,
        )
        for site in self.config.site_names:
            runner = NodeCommandRunner(self.routers[site])
            self._address(
                runner, f"{site}-mgmt",
                f"{self.config.management_ip(site)}/{self.config.management_network.prefixlen}",
            )
            for path, underlay in self.config.underlays.items():
                self._address(
                    runner, f"{site}-{path}",
                    f"{self.config.underlay_ip(site, path)}/{underlay.network.prefixlen}",
                )
            if site in self.config.spokes:
                spoke = self.config.spokes[site]
                self._address(
                    runner, f"{site}-lan", f"{spoke.lan_gateway}/{spoke.lan_network.prefixlen}",
                )
        for spoke in self.config.spokes.values():
            for number in (1, 2, 3):
                name = f"{spoke.name}-h{number}"
                runner = NodeCommandRunner(self.hosts[name])
                interface = str(self.hosts[name].defaultIntf())
                self._address(
                    runner, interface, f"{spoke.host_ip(number)}/{spoke.lan_network.prefixlen}",
                )
                runner.run(f"ip route replace default via {spoke.lan_gateway}", f"default route {name}")

    def _keys(self) -> None:
        for site in self.config.site_names:
            runner = NodeCommandRunner(self.routers[site])
            key = f"/run/sdwan-keys/{site}.priv"
            runner.run(f"umask 077 && wg genkey > {key} && chmod 600 {key}", "generate private WG key")
            public = runner.run(f"wg pubkey < {key}", "derive public WG key").stdout.strip()
            if len(public) != 44:
                raise RuntimeError(f"{site}: invalid WireGuard public key")
            self.public_keys[site] = public

    def _agents(self) -> None:
        for site in self.config.site_names:
            command = [
                "/opt/sdwan/venv/bin/python", "-m", "sdwan_v4.edge_agent_v4",
                "--site", site, "--config-dir", "/opt/sdwan_v4/config",
                "--private-key", f"/run/sdwan-keys/{site}.priv",
                "--controller-url", self.controller_url,
                "--port", str(self.config.controller.edge_port),
                "--bind", str(self.config.management_ip(site)),
            ]
            self.agents[site] = self.routers[site].popen(command, text=True)
        deadline = time.monotonic() + 25
        pending = set(self.config.site_names)
        while pending and time.monotonic() < deadline:
            for site in list(pending):
                process = self.agents[site]
                if process.poll() is not None:
                    raise RuntimeError(f"{site} Edge agent exited: {process.returncode}")
                try:
                    response = requests.get(self.edge_url(site, "/healthz"), timeout=0.3)
                    if response.status_code == 200:
                        pending.remove(site)
                except requests.RequestException:
                    pass
            time.sleep(0.2)
        if pending:
            raise RuntimeError(f"Edge agents not ready: {sorted(pending)}")

    def _register(self) -> None:
        response = requests.post(
            f"{self.controller_url}/sdwan/register", json={"public_keys": self.public_keys},
            headers=self.headers, timeout=5,
        )
        response.raise_for_status()
        deadline = time.monotonic() + 30
        pending = set(self.config.site_names)
        while pending and time.monotonic() < deadline:
            for site in list(pending):
                try:
                    state = requests.get(
                        self.edge_url(site), headers=self.headers, timeout=0.5,
                    ).json()
                    if int(state.get("reconcile_version", 0)) > 0:
                        pending.remove(site)
                except (requests.RequestException, ValueError):
                    pass
            time.sleep(0.25)
        if pending:
            raise RuntimeError(f"initial desired state not reconciled: {sorted(pending)}")

    def verify(self) -> None:
        if self.net is None:
            raise RuntimeError("topology is not running")
        expected = {item.dpid for item in self.config.underlays.values()}
        expected.update(item.lan_dpid for item in self.config.spokes.values())
        deadline = time.monotonic() + 10
        connected: set[int] = set()
        while connected != expected and time.monotonic() < deadline:
            response = requests.get(
                f"{self.controller_url}/sdwan/state/node1", headers=self.headers, timeout=2,
            )
            response.raise_for_status()
            connected = {
                int(value) for value in
                response.json().get("openflow", {}).get("connected_dpids", [])
            }
            if connected != expected:
                time.sleep(0.25)
        if connected != expected:
            raise RuntimeError(f"OpenFlow datapaths connected={sorted(connected)} expected={sorted(expected)}")
        for site in self.config.spokes:
            router = NodeCommandRunner(self.routers[site])
            state = self.edge_state(site)
            if not state.get("classifier_alive"):
                raise RuntimeError(f"{site}: native classifier is not healthy")
            rules = router.run("ip rule show", f"verify policy rules {site}").stdout
            for table in (101, 102, 103):
                if f"lookup {table}" not in rules:
                    raise RuntimeError(f"{site}: routing table {table} has no fwmark rule")
            chains = router.run(
                "iptables -t mangle -S SDWAN_V4_OUT && iptables -t mangle -S SDWAN_V4_IN",
                f"verify classifier chains {site}",
            ).stdout
            if "NFQUEUE" not in chains or "CONNMARK" not in chains:
                raise RuntimeError(f"{site}: classifier chains are incomplete")
            queue_state = router.run(
                "cat /proc/net/netfilter/nfnetlink_queue", f"verify NFQUEUE listeners {site}",
            ).stdout
            queue_numbers = {int(line.split()[0]) for line in queue_state.splitlines() if line.split()}
            expected_queues = set(range(
                self.config.settings.nfqueue_start, self.config.settings.nfqueue_end + 1,
            ))
            if not expected_queues.issubset(queue_numbers):
                raise RuntimeError(f"{site}: NFQUEUE listeners={sorted(queue_numbers)}")
            hub = self.config.spokes[site].home_hub
            for path, underlay in self.config.underlays.items():
                router.run(
                    f"ping -c 1 -W 2 -I {underlay.wireguard_interface} "
                    f"{self.config.overlay_ip(hub, path)}",
                    f"verify {site} {path} WireGuard path",
                )
                peers = router.run(
                    f"wg show {underlay.wireguard_interface} peers",
                    f"verify {site} {path} WireGuard peer",
                ).stdout.split()
                if not peers:
                    raise RuntimeError(f"{site}: {underlay.wireguard_interface} has no peer")
        for spoke in self.config.spokes.values():
            runner = NodeCommandRunner(self.hosts[f"{spoke.name}-h1"])
            runner.run(f"ping -c 1 -W 2 {spoke.lan_gateway}", f"verify LAN {spoke.name}")
        NodeCommandRunner(self.hosts["node1-h1"]).run(
            f"ping -c 1 -W 3 {self.config.spokes['node2'].host_ip(1)}",
            "verify intersite overlay forwarding",
        )

    def smoke_protocols(self) -> None:
        """Run real services plus explicit generic/negative protocol fixtures."""
        server = self.hosts["node2-h1"]
        client = NodeCommandRunner(self.hosts["node1-h1"])
        server_ip = str(self.config.spokes["node2"].host_ip(1))
        NodeCommandRunner(server).run(
            "sh /opt/sdwan_v4/workloads/start_test_services.sh 200",
            "start HTTP HTTPS SSH FTP DNS and QUIC services", timeout_s=45,
        )
        tcp_server = server.popen([
            "python3", "/opt/sdwan_v4/workloads/tcp_test.py", "server",
            "--bind", server_ip,
        ], text=True)
        udp_server = server.popen([
            "python3", "/opt/sdwan_v4/workloads/udp_test.py", "server",
            "--bind", server_ip,
        ], text=True)
        self.load_processes.extend([tcp_server, udp_server])
        time.sleep(1)
        commands = [
            (f"python3 /opt/sdwan_v4/workloads/tcp_test.py client {server_ip} --flow-id live-tcp", "generic TCP"),
            (f"python3 /opt/sdwan_v4/workloads/udp_test.py client {server_ip} --flow-id live-udp", "generic UDP"),
            (f"curl --fail --output /dev/null http://{server_ip}/healthz", "HTTP"),
            (f"curl --fail --insecure --output /dev/null https://{server_ip}/healthz", "HTTPS"),
            (f"dig @{server_ip} sdwan-lab.local A +time=2 +tries=1", "DNS"),
            (f"python3 /opt/sdwan_v4/workloads/quic_test.py client {server_ip}", "real QUIC"),
            (f"curl --fail --range 0-1048575 --output /dev/null ftp://{server_ip}/sdwan-200M.bin", "FTP"),
            ("ssh -i /opt/sdwan-lab-ssh/id_ed25519 -o StrictHostKeyChecking=no "
             f"-o UserKnownHostsFile=/dev/null sdwan@{server_ip} true", "SSH"),
        ]
        for command, name in commands:
            client.run(command, f"protocol smoke test: {name}", timeout_s=45)
        for fixture in ("sip", "stun", "rtp", "udp443-nonquic"):
            client.run(
                f"python3 /opt/sdwan_v4/workloads/protocol_fixtures.py {fixture} {server_ip}",
                f"protocol fixture: {fixture}", timeout_s=15,
            )

    def shape(self, site: str, path: str, delay_ms: float, loss_pct: float, jitter_ms: float) -> None:
        self._validate_site_path(site, path)
        capacity = self.config.underlays[path].bandwidth_mbps
        NodeCommandRunner(self.routers[site]).run(
            f"tc qdisc replace dev {site}-{path} root netem rate {capacity}mbit "
            f"delay {delay_ms}ms {jitter_ms}ms loss {loss_pct}%",
            f"degrade {site} {path}",
        )

    def restore(self, site: str, path: str) -> None:
        self._validate_site_path(site, path)
        value = self.config.underlays[path]
        self.shape(site, path, value.delay_ms, value.loss_pct, value.jitter_ms)

    def link(self, site: str, path: str, up: bool) -> None:
        self._validate_site_path(site, path)
        NodeCommandRunner(self.routers[site]).run(
            f"ip link set dev {site}-{path} {'up' if up else 'down'}",
            f"link {'up' if up else 'down'} {site} {path}",
        )

    def saturate(self, site: str, path: str, rate: str) -> None:
        self._validate_site_path(site, path)
        hub = self.config.spokes.get(site).home_hub if site in self.config.spokes else "hub1"
        port = 5400 + self.config.underlays[path].mark
        server = self.routers[hub].popen(["iperf3", "-s", "-1", "-p", str(port)], text=True)
        client = self.routers[site].popen([
            "iperf3", "-c", str(self.config.underlay_ip(hub, path)), "-B",
            str(self.config.underlay_ip(site, path)), "-p", str(port), "-u", "-b", rate, "-t", "300",
        ], text=True)
        self.load_processes.extend([server, client])

    def _validate_site_path(self, site: str, path: str) -> None:
        if site not in self.config.site_names or path not in self.config.underlays:
            raise ValueError("unknown site or path")

    def edge_state(self, site: str) -> dict[str, Any]:
        if site not in self.config.site_names:
            raise ValueError("unknown site")
        response = requests.get(self.edge_url(site), headers=self.headers, timeout=2)
        response.raise_for_status()
        return response.json()

    def stop(self) -> None:
        for process in self.load_processes:
            if process.poll() is None:
                process.terminate()
        for process in self.agents.values():
            if process.poll() is None:
                process.terminate()
        for process in self.agents.values():
            try:
                process.wait(timeout=3)
            except Exception:
                if process.poll() is None:
                    process.kill()
        if self.net is not None:
            self.net.stop()
            self.net = None
        resolved = self.runtime_dir.resolve()
        if resolved.name.startswith("sdwan-v4-keys-") and resolved.parent == Path(tempfile.gettempdir()).resolve():
            shutil.rmtree(resolved, ignore_errors=True)


def _print(value: Any) -> None:
    print(json.dumps(value, indent=2, default=str))


def run_cli(lab: SDWANLab) -> None:
    from mininet.cli import CLI

    class SDWANCLI(CLI):
        prompt = "sdwan-v4> "

        def do_degrade(self, line: str) -> None:
            "degrade <site> <path> <delay-ms> <loss-pct> <jitter-ms>"
            try:
                site, path, delay, loss, jitter = line.split()
                lab.shape(site, path, float(delay), float(loss), float(jitter))
            except (ValueError, requests.RequestException) as exc:
                print(f"error: {exc}")

        def do_degradeall(self, line: str) -> None:
            "degradeall <path> <delay-ms> <loss-pct> <jitter-ms> (explicit global scope)"
            try:
                path, delay, loss, jitter = line.split()
                for site in lab.config.site_names:
                    lab.shape(site, path, float(delay), float(loss), float(jitter))
            except ValueError as exc:
                print(f"error: {exc}")

        def do_restore(self, line: str) -> None:
            "restore <site> <path>"
            try:
                lab.restore(*line.split())
            except (TypeError, ValueError) as exc:
                print(f"error: {exc}")

        def do_linkdown(self, line: str) -> None:
            "linkdown <site> <path>"
            try:
                lab.link(*line.split(), up=False)
            except (TypeError, ValueError) as exc:
                print(f"error: {exc}")

        def do_linkup(self, line: str) -> None:
            "linkup <site> <path>"
            try:
                lab.link(*line.split(), up=True)
            except (TypeError, ValueError) as exc:
                print(f"error: {exc}")

        def do_saturate(self, line: str) -> None:
            "saturate <site> <path> <rate>, e.g. saturate node1 bb 45M"
            try:
                lab.saturate(*line.split())
            except (TypeError, ValueError) as exc:
                print(f"error: {exc}")

        def do_showflows(self, line: str) -> None:
            "showflows <site>"
            site = line.strip()
            try:
                print(NodeCommandRunner(lab.routers[site]).run(
                    "conntrack -L -o extended", "show flows", accepted=(0, 1),
                ).stdout)
            except (KeyError, ValueError) as exc:
                print(f"error: {exc}")

        def do_showclassifications(self, line: str) -> None:
            "showclassifications <site>"
            try:
                _print(lab.edge_state(line.strip())["recent_classifications"])
            except (KeyError, ValueError, requests.RequestException) as exc:
                print(f"error: {exc}")

        def do_showqueues(self, line: str) -> None:
            "showqueues <site>"
            site = line.strip()
            try:
                print(NodeCommandRunner(lab.routers[site]).run("tc -s qdisc show", "show queues").stdout)
                _print(lab.edge_state(site).get("classifier_stats", {}))
            except (KeyError, requests.RequestException) as exc:
                print(f"error: {exc}")

        def do_showcache(self, line: str) -> None:
            "showcache <site>"
            try:
                stats = lab.edge_state(line.strip()).get("classifier_stats", {})
                _print({"application_evidence_entries": stats.get("application_evidence_entries", 0)})
            except (ValueError, requests.RequestException) as exc:
                print(f"error: {exc}")

        def do_showoverrides(self, line: str) -> None:
            "showoverrides <spoke>"
            try:
                response = requests.get(
                    f"{lab.controller_url}/sdwan/state/{line.strip()}",
                    headers=lab.headers, timeout=2,
                )
                response.raise_for_status()
                _print(response.json()["policy"]["overrides"])
            except (KeyError, requests.RequestException) as exc:
                print(f"error: {exc}")

    if lab.net is None:
        raise RuntimeError("topology is not running")
    SDWANCLI(lab.net)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-dir", type=Path, default=CONFIG_DIR)
    parser.add_argument("--no-cli", action="store_true")
    parser.add_argument("--smoke-protocols", action="store_true")
    args = parser.parse_args()
    bundle = load_bundle(args.config_dir)
    lab = SDWANLab(bundle)
    try:
        lab.build()
        if args.smoke_protocols:
            lab.smoke_protocols()
        if not args.no_cli:
            run_cli(lab)
    finally:
        lab.stop()


if __name__ == "__main__":
    main()
