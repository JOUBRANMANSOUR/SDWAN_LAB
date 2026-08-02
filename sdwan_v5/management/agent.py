"""Fail-closed, mockable external-agent boundary for the web gateway."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol
import shutil

@dataclass(frozen=True)
class AgentResult:
    status: str
    events: tuple[dict, ...]
    reply: str

class AgentRunner(Protocol):
    def run(self, prompt: str, session_id: int) -> AgentResult: ...

class AvailabilityRunner:
    """Never launches a shell; reports prerequisites for a reviewed runtime runner."""
    def run(self, prompt: str, session_id: int) -> AgentResult:
        missing=[name for name in ("claude","ollama") if shutil.which(name) is None]
        if missing:
            return AgentResult("UNAVAILABLE", ({"type":"agent_error","reason":"missing runtime: "+", ".join(missing)},), "External Agent Gateway is unavailable; use the approved read-only REST/MCP evidence endpoints.")
        return AgentResult("CONFIGURED_NOT_EXECUTED", ({"type":"agent_error","reason":"external execution is disabled pending reviewed least-privilege configuration"},), "External Agent Gateway is configured but deliberately not executed by this laboratory service.")
