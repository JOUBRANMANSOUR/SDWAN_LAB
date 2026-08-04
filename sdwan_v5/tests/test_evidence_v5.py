from __future__ import annotations
import unittest
from sdwan_v5.management.evidence import EvidenceValidator, render_verified_answer

BUNDLE={"bundle_id":"bundle-1","payload":{"facts":[{"fact_id":"f-route","fact_kind":"selected_routing_table","value":1101},{"fact_id":"f-interface","fact_kind":"output_interface","value":"wg-h1-mpls"}],"sources":[{"source_id":"s1"}],"unknowns":[],"limitations":[]}}
class EvidenceTests(unittest.TestCase):
    def setUp(self): self.validator=EvidenceValidator()
    def test_valid_operational_claims_render_only_fact_values(self):
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"c1","claim_type":"routing_table","fact_ids":["f-route"],"explanation":"ignored"}],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,BUNDLE)
        self.assertTrue(result["valid"])
        rendered=render_verified_answer(result,BUNDLE)
        self.assertIn('1101',rendered); self.assertNotIn('ignored',rendered)
    def test_route_facts_render_as_tables_without_model_text(self):
        bundle={"bundle_id":"bundle-routes","payload":{"facts":[
            {"fact_id":"groups","fact_kind":"route_groups","value":[{"table":"101","output_interface":"wg-h1-mpls","hub":"hub1","transport":"mpls","next_hop":None,"destinations":["10.2.0.0/24"]}]},
            {"fact_id":"rules","fact_kind":"routing_rules","value":[{"priority":2001,"fwmark":"0x1","fwmask":"0xff","table":"101","src":"all"}]}
        ],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[
            {"claim_id":"groups","claim_type":"routing_table","fact_ids":["groups"],"explanation":None},
            {"claim_id":"rules","claim_type":"routing_rule","fact_ids":["rules"],"explanation":None}
        ],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,bundle)
        rendered=render_verified_answer(result,bundle)
        self.assertIn("| Table | Interface | Hub |", rendered)
        self.assertIn("| Priority | FWMark |", rendered)
        self.assertNotIn("ignored", rendered)

    def test_tunnel_facts_render_as_observed_table_without_key_material(self):
        raw="""interface: wg-h1-mpls
  public key: public-value
  private key: (hidden)
  listening port: 52000

peer: peer-value
  endpoint: 192.168.10.1:52000
  allowed ips: 10.2.0.0/24
  latest handshake: 12 seconds ago
  transfer: 1 KiB received, 2 KiB sent
  persistent keepalive: every 10 seconds
"""
        bundle={"bundle_id":"bundle-tunnels","payload":{"facts":[{"fact_id":"tunnels","fact_kind":"tunnels","value":{"availability":"AVAILABLE","value":raw}}],"unknowns":[],"limitations":[]}}
        answer={"answer_type":"operational","summary":"ignored","claims":[{"claim_id":"tunnels","claim_type":"tunnel_status","fact_ids":["tunnels"],"explanation":None}],"unknowns":[],"limitations":[]}
        rendered=render_verified_answer(self.validator.validate(answer,bundle),bundle)
        self.assertIn("| Interface | Endpoint |", rendered)
        self.assertIn("wg-h1-mpls", rendered)
        self.assertNotIn("public-value", rendered)
        self.assertNotIn("private key", rendered)

    def test_unknown_fact_and_wrong_kind_are_rejected(self):
        unknown={"answer_type":"operational","summary":"x","claims":[{"claim_id":"c","claim_type":"route","fact_ids":["missing"],"explanation":None}],"unknowns":[],"limitations":[]}
        self.assertFalse(self.validator.validate(unknown,BUNDLE)["valid"])
        wrong={"answer_type":"operational","summary":"x","claims":[{"claim_id":"c","claim_type":"route","fact_ids":["f-interface"],"explanation":None}],"unknowns":[],"limitations":[]}
        self.assertFalse(self.validator.validate(wrong,BUNDLE)["valid"])
    def test_operational_answer_without_evidence_is_rejected(self):
        answer={"answer_type":"operational","summary":"x","claims":[],"unknowns":[],"limitations":[]}
        result=self.validator.validate(answer,{"payload":{"facts":[]}})
        self.assertFalse(result["valid"])
        self.assertIn("NO_MCP_EVIDENCE",[item["code"] for item in result["errors"]])
