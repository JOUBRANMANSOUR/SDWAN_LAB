#!/usr/bin/env python3
"""Ryu OpenFlow 1.3 underlay controller.

Application classification and SD-WAN path policy intentionally live outside
this process in policy_service_v4.py.
"""
from __future__ import annotations

import json
import logging
import os
import time
from typing import Any

import requests

from .config_loader_v4 import load_bundle

LOG = logging.getLogger("sdwan.controller.v4")

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import (
        CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls,
    )
    from ryu.lib import hub
    from ryu.lib.packet import ethernet, ether_types, packet
    from ryu.ofproto import ofproto_v1_3
    RYU_AVAILABLE = True
except ImportError:
    RYU_AVAILABLE = False


if RYU_AVAILABLE:
    class SDWANUnderlayController(app_manager.RyuApp):
        """Learning-switch forwarding and underlay counters only."""

        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args: Any, **kwargs: Any):
            super().__init__(*args, **kwargs)
            bundle = load_bundle()
            config = bundle.topology
            host = config.controller.management_address.split("/", 1)[0]
            self.policy_url = f"http://{host}:{config.controller.policy_port}"
            token = os.getenv(config.controller.shared_token_env, "")
            self.headers = {"X-SDWAN-Token": token} if token else {}
            self.mac_to_port: dict[int, dict[str, int]] = {}
            self.datapaths: dict[int, Any] = {}
            self.monitor = hub.spawn(self._monitor)

        def add_flow(
            self, datapath: Any, priority: int, match: Any, actions: list[Any],
            buffer_id: int | None = None, idle_timeout: int = 0,
        ) -> None:
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            instructions = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            kwargs: dict[str, Any] = {
                "datapath": datapath,
                "priority": priority,
                "match": match,
                "instructions": instructions,
                "idle_timeout": idle_timeout,
            }
            if buffer_id is not None and buffer_id != ofproto.OFP_NO_BUFFER:
                kwargs["buffer_id"] = buffer_id
            datapath.send_msg(parser.OFPFlowMod(**kwargs))

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features(self, event: Any) -> None:
            datapath = event.msg.datapath
            parser = datapath.ofproto_parser
            ofproto = datapath.ofproto
            self.add_flow(
                datapath, 0, parser.OFPMatch(),
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)],
            )

        @set_ev_cls(
            ofp_event.EventOFPStateChange,
            [MAIN_DISPATCHER, DEAD_DISPATCHER],
        )
        def state_change(self, event: Any) -> None:
            datapath = event.datapath
            if event.state == MAIN_DISPATCHER:
                self.datapaths[datapath.id] = datapath
            elif event.state == DEAD_DISPATCHER:
                self.datapaths.pop(datapath.id, None)
            hub.spawn(self._publish_datapath_state)

        def _publish_datapath_state(self) -> None:
            payload = {
                "timestamp": time.time(),
                "connected_dpids": sorted(self.datapaths),
            }
            try:
                requests.post(
                    f"{self.policy_url}/sdwan/openflow-state", json=payload,
                    headers=self.headers, timeout=1,
                ).raise_for_status()
            except requests.RequestException as exc:
                LOG.debug("policy service unavailable for datapath state: %s", exc)

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def packet_in(self, event: Any) -> None:
            msg = event.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match["in_port"]
            parsed = packet.Packet(msg.data)
            eth = parsed.get_protocol(ethernet.ethernet)
            if eth is None or eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return
            table = self.mac_to_port.setdefault(datapath.id, {})
            table[eth.src] = in_port
            out_port = table.get(eth.dst, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_src=eth.src, eth_dst=eth.dst)
                self.add_flow(datapath, 10, match, actions, msg.buffer_id, idle_timeout=120)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    return
            datapath.send_msg(parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data,
            ))

        def _monitor(self) -> None:
            while True:
                hub.spawn(self._publish_datapath_state)
                for datapath in list(self.datapaths.values()):
                    parser = datapath.ofproto_parser
                    datapath.send_msg(parser.OFPPortStatsRequest(datapath, 0, datapath.ofproto.OFPP_ANY))
                hub.sleep(5)

        @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
        def port_stats(self, event: Any) -> None:
            datapath = event.msg.datapath
            payload = {
                "timestamp": time.time(),
                "dpid": datapath.id,
                "ports": [
                    {
                        "port_no": item.port_no,
                        "rx_packets": item.rx_packets,
                        "tx_packets": item.tx_packets,
                        "rx_bytes": item.rx_bytes,
                        "tx_bytes": item.tx_bytes,
                        "rx_dropped": item.rx_dropped,
                        "tx_dropped": item.tx_dropped,
                        "rx_errors": item.rx_errors,
                        "tx_errors": item.tx_errors,
                    }
                    for item in event.msg.body
                    if item.port_no < datapath.ofproto.OFPP_MAX
                ],
            }
            hub.spawn(self._publish_stats, payload)

        def _publish_stats(self, payload: dict[str, Any]) -> None:
            try:
                requests.post(
                    f"{self.policy_url}/sdwan/underlay-stats",
                    data=json.dumps(payload),
                    headers={**self.headers, "Content-Type": "application/json"},
                    timeout=1,
                ).raise_for_status()
            except requests.RequestException as exc:
                LOG.debug("policy service unavailable for port stats: %s", exc)


def main() -> None:
    if not RYU_AVAILABLE:
        raise SystemExit("run this module through ryu-manager in the Ryu virtual environment")


if __name__ == "__main__":
    main()
