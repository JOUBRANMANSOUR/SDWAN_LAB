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
            "site_status": {"sites", "site", "lan_prefix", "preferred_hub", "standby_hub", "status", "configured", "desired", "runtime", "links", "tunnels", "routes", "rules", "failover", "classifier"},
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

def _markdown(value: Any) -> str:
    """Render evidence values without adding operational interpretation."""
    if value is None:
        return "not reported"
    return str(value).replace("|", "\\|").replace("\n", " ")

def _route_groups_table(groups: Any) -> List[str]:
    if not isinstance(groups, list):
        return ["- **route_groups**: `{}`".format(json.dumps(groups, sort_keys=True, default=str))]
    lines=["| Table | Interface | Hub | Transport | Next hop | Destinations |", "|---|---|---|---|---|---|"]
    for group in groups:
        if not isinstance(group, dict):
            lines.append("| not reported | not reported | not reported | not reported | not reported | `{}` |".format(_markdown(group)))
            continue
        destinations=group.get("destinations", [])
        destination_text=", ".join(_markdown(item) for item in destinations) if isinstance(destinations, list) else _markdown(destinations)
        lines.append("| {} | {} | {} | {} | {} | {} |".format(
            _markdown(group.get("table")), _markdown(group.get("output_interface")),
            _markdown(group.get("hub")), _markdown(group.get("transport")),
            _markdown(group.get("next_hop")), destination_text or "not reported"))
    return lines

def _routing_rules_table(rules: Any) -> List[str]:
    if not isinstance(rules, list):
        return ["- **routing_rules**: `{}`".format(json.dumps(rules, sort_keys=True, default=str))]
    lines=["| Priority | FWMark | Mask | Table | Source |", "|---|---|---|---|---|"]
    for rule in rules:
        if not isinstance(rule, dict):
            lines.append("| not reported | not reported | not reported | not reported | not reported |")
            continue
        lines.append("| {} | {} | {} | {} | {} |".format(
            _markdown(rule.get("priority")), _markdown(rule.get("fwmark")),
            _markdown(rule.get("fwmask")), _markdown(rule.get("table")),
            _markdown(rule.get("src"))))
    return lines

def _render_fact(fact: Dict[str, Any]) -> List[str]:
    kind=str(fact.get("fact_kind", "evidence"))
    value=fact.get("value")
    if kind == "route_groups":
        return ["### Installed route groups"] + _route_groups_table(value)
    if kind == "routing_rules":
        return ["### Installed policy rules"] + _routing_rules_table(value)
    return ["- **{}**: `{}`".format(kind, json.dumps(value, sort_keys=True, default=str))]

def render_verified_answer(validation: Dict[str, Any], bundle: Dict[str, Any]) -> str:
    answer=validation["answer"]
    if answer["answer_type"] == "conceptual":
        return "## Conceptual explanation\n\n" + answer["summary"]
    facts={str(item.get("fact_id")):item for item in bundle["payload"].get("facts",[]) if item.get("fact_id")}
    lines=["## Verified operational facts"]
    for claim in answer["claims"]:
        for fact_id in claim["fact_ids"]:
            fact=facts[fact_id]
            rendered=_render_fact(fact)
            if rendered and rendered[0].startswith("###"):
                lines.append("\n" + rendered[0])
                lines.extend(rendered[1:])
            else:
                lines.append("\n### {}".format(claim["claim_type"]))
                lines.extend(rendered)
    unknowns=bundle["payload"].get("unknowns",[])
    limitations=bundle["payload"].get("limitations",[])
    if unknowns:
        lines.extend(["\n## Unknown or unavailable information"]+["- {}: {}".format(item.get("field"),item.get("reason")) for item in unknowns[:32]])
    if limitations:
        lines.extend(["\n## Evidence limitations"]+["- {}".format(item) for item in limitations[:32]])
    lines.append("\nEvidence bundle: `{}`".format(bundle["bundle_id"]))
    return "\n".join(lines)
