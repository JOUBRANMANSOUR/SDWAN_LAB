"""Safe Ollama -> Claude Code subprocess runner for the read-only web agent."""
from __future__ import annotations
import asyncio, json, uuid
from dataclasses import dataclass
from typing import AsyncIterator, Dict, List
from .auth import Principal, issue_agent_context
from .config import ManagementConfig
@dataclass(frozen=True)
class AgentEvent:
    type: str
    data: Dict[str, object]
def command_for(config: ManagementConfig, prompt: str, session_id: str, resume: bool = False) -> List[str]:
    session_option = ["--resume", session_id] if resume else ["--session-id", session_id]
    return [config.ollama_executable, "launch", "claude", "--model", config.ollama_model, "--yes", "--", "-p", prompt, "--output-format", "stream-json", "--verbose", "--include-partial-messages", "--mcp-config", str(config.mcp_config), "--strict-mcp-config", "--settings", str(config.claude_settings)] + session_option
def restricted_environment(config: ManagementConfig, context_token: str, session_id: str) -> Dict[str, str]:
    return {"HOME": config.claude_home, "PATH": config.agent_path, "SDWAN_PROJECT_ROOT": str(config.project_root), "PYTHONPATH": str(config.project_root.parent), "SDWAN_AGENT_CONTEXT_TOKEN": context_token, "SDWAN_CHAT_SESSION_ID": session_id, "SDWAN_MANAGEMENT_SECRET": config.signing_secret, "SDWAN_AGENT_CONTEXT_AUDIENCE": config.agent_context_audience}
def normalized_event(raw: Dict[str, object]) -> AgentEvent:
    """Expose only text deltas and safe MCP activity; never reasoning events."""
    kind = str(raw.get("type", ""))
    if kind == "result":
        return AgentEvent("agent_completed", {"session_id": str(raw.get("session_id", ""))})
    if kind != "stream_event":
        return AgentEvent("ignore", {})
    event = raw.get("event", {})
    event = event if isinstance(event, dict) else {}
    event_type = str(event.get("type", ""))
    if event_type == "content_block_delta":
        delta = event.get("delta", {})
        delta = delta if isinstance(delta, dict) else {}
        if delta.get("type") == "text_delta" and delta.get("text"):
            return AgentEvent("assistant_delta", {"text": str(delta["text"])[:8192]})
    if event_type == "content_block_start":
        block = event.get("content_block", {})
        block = block if isinstance(block, dict) else {}
        if block.get("type") == "tool_use":
            return AgentEvent("tool_call_started", {"tool": str(block.get("name", "sdwan"))[:120]})
    if event_type == "content_block_stop":
        return AgentEvent("tool_call_completed", {})
    return AgentEvent("ignore", {})

class OllamaClaudeRunner:
    def __init__(self, config: ManagementConfig):
        self.config=config
        self._started_sessions = set()
    async def run(self, prompt: str, session_id: str, principal: Principal) -> AsyncIterator[AgentEvent]:
        token=issue_agent_context(self.config.signing_secret, principal, session_id, self.config.agent_context_audience, self.config.agent_context_ttl_seconds)
        claude_session_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "sdwan-v5-web-session:" + session_id))
        factual_prompt = ("You are a read-only SD-WAN diagnostic assistant. Use only approved SD-WAN MCP tools for current facts. "
                          "Do not infer, invent, rename, or generalize facts beyond returned fields. Do not describe an absent field as main, kernel, static, DNS, SIMPL, or any other route type. "
                          "For empty or null values say 'not reported'. State unavailable when evidence is absent. "
                          "Unless the user explicitly asks for raw JSON, answer in concise natural language with compact Markdown tables; summarize route groups instead of listing every repeated destination. "
                          "Never suggest or perform configuration changes.\n\nUser question: " + prompt)
        resume = claude_session_id in self._started_sessions
        cmd=command_for(self.config, factual_prompt, claude_session_id, resume=resume); env=restricted_environment(self.config, token, session_id)
        if not self.config.mcp_config.is_file() or not self.config.claude_settings.is_file():
            yield AgentEvent("agent_error", {"reason":"agent configuration is unavailable"}); return
        try:
            proc=await asyncio.create_subprocess_exec(*cmd, cwd=str(self.config.project_root), env=env, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except (OSError, ValueError):
            yield AgentEvent("agent_error", {"reason":"agent runtime is unavailable"}); return
        collected=0; saw_text=False; final_text=""
        try:
            while True:
                line=await asyncio.wait_for(proc.stdout.readline(), timeout=self.config.claude_timeout_seconds)
                if not line: break
                collected += len(line)
                if collected > self.config.claude_max_output_bytes: raise RuntimeError("agent output limit exceeded")
                try: raw=json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError): continue
                if not isinstance(raw, dict): continue
                if raw.get("type") == "assistant":
                    message=raw.get("message", {}); content=message.get("content", []) if isinstance(message, dict) else []
                    final_text="".join(str(part.get("text", "")) for part in content if isinstance(part, dict) and part.get("type") == "text")
                elif raw.get("type") == "result":
                    final_text=str(raw.get("result", final_text))
                event = normalized_event(raw)
                if event.type == "assistant_delta": saw_text=True
                if event.type != "ignore": yield event
            stderr=await asyncio.wait_for(proc.stderr.read(self.config.claude_max_output_bytes + 1), timeout=10)
            code=await asyncio.wait_for(proc.wait(), timeout=10)
            if len(stderr) > self.config.claude_max_output_bytes or code != 0: yield AgentEvent("agent_error", {"reason":"agent process did not complete successfully", "exit_code":code})
            else:
                self._started_sessions.add(claude_session_id)
                if final_text and not saw_text: yield AgentEvent("assistant_delta", {"text":final_text[:8192]})
                yield AgentEvent("agent_completed", {"session_id":session_id})
        except (asyncio.TimeoutError, RuntimeError):
            proc.terminate()
            try: await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError: proc.kill()
            yield AgentEvent("agent_error", {"reason":"agent execution timed out or exceeded bounds"})
