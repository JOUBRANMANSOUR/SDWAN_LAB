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
