"""Deterministic evidence validation and operational rendering."""
from __future__ import annotations
import json
from typing import Any, Dict, List
from pydantic import ValidationError
from sdwan_v5.sdwan_mcp.models.answers import AgentAnswer, AnswerType

class EvidenceValidator:
    def validate(self, answer_data: Dict[str, Any], bundle: Dict[str, Any]) -> Dict[str, Any]:
        try:
            answer=AgentAnswer.model_validate(answer_data)
        except ValidationError as exc:
            return {"valid":False,"errors":[{"code":"ANSWER_SCHEMA_INVALID","detail":str(exc)[:256]}],"validated_claims":[],"rejected_claims":[]}
        facts={str(item.get("fact_id")):item for item in bundle["payload"].get("facts",[]) if item.get("fact_id")}
        errors=[]; accepted=[]
        compatible = {
            "site_status": {"sites", "site", "configured", "desired", "runtime", "links", "tunnels", "routes", "rules", "failover", "classifier"},
            "tunnel_status": {"tunnels"}, "routing_rule": {"routing_rules", "matched_rule"},
            "routing_table": {"selected_routing_table", "route_groups"}, "route": {"matched_route", "routes", "route_groups"},
            "next_hop": {"next_hop", "matched_route"}, "output_interface": {"output_interface", "matched_route", "route_groups"},
            "selected_hub": {"derived"}, "selected_transport": {"derived"},
            "state_comparison": {"comparisons"}, "event": {"events"}, "limitation": {"limitations"},
        }
        if answer.answer_type in (AnswerType.operational, AnswerType.mixed) and not answer.claims:
            errors.append({"code":"OPERATIONAL_CLAIMS_REQUIRED"})
        for claim in answer.claims:
            if answer.answer_type == AnswerType.conceptual:
                errors.append({"code":"CONCEPTUAL_ANSWER_HAS_OPERATIONAL_CLAIM","claim_id":claim.claim_id}); continue
            if not claim.fact_ids:
                errors.append({"code":"CLAIM_EVIDENCE_REQUIRED","claim_id":claim.claim_id}); continue
            missing=[fact_id for fact_id in claim.fact_ids if fact_id not in facts]
            if missing:
                errors.append({"code":"UNKNOWN_FACT_ID","claim_id":claim.claim_id,"fact_ids":missing}); continue
            if not all(facts[fact_id].get("fact_kind") in compatible.get(claim.claim_type, set()) for fact_id in claim.fact_ids):
                errors.append({"code":"CLAIM_FACT_KIND_MISMATCH","claim_id":claim.claim_id}); continue
            accepted.append(claim.claim_id)
        if answer.answer_type in (AnswerType.operational, AnswerType.mixed) and not facts:
            errors.append({"code":"NO_MCP_EVIDENCE"})
        return {"valid":not errors,"answer":answer.model_dump(mode="json"),"validated_claims":accepted,"rejected_claims":[item.get("claim_id") for item in errors if item.get("claim_id")],"errors":errors}

def render_verified_answer(validation: Dict[str, Any], bundle: Dict[str, Any]) -> str:
    answer=validation["answer"]
    if answer["answer_type"] == "conceptual":
        return "## Conceptual explanation\n\n" + answer["summary"]
    facts={str(item.get("fact_id")):item for item in bundle["payload"].get("facts",[]) if item.get("fact_id")}
    lines=["## Verified operational facts"]
    for claim in answer["claims"]:
        lines.append("\n### {}".format(claim["claim_type"]))
        for fact_id in claim["fact_ids"]:
            fact=facts[fact_id]
            lines.append("- **{}**: `{}`".format(fact["fact_kind"], json.dumps(fact.get("value"), sort_keys=True, default=str)))
    unknowns=bundle["payload"].get("unknowns",[])
    limitations=bundle["payload"].get("limitations",[])
    if unknowns:
        lines.extend(["\n## Unknown or unavailable information"]+["- {}: {}".format(item.get("field"),item.get("reason")) for item in unknowns[:32]])
    if limitations:
        lines.extend(["\n## Evidence limitations"]+["- {}".format(item) for item in limitations[:32]])
    lines.append("\nEvidence bundle: `{}`".format(bundle["bundle_id"]))
    return "\n".join(lines)
