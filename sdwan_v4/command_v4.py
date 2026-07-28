"""Checked Linux command execution used by topology and Edge components."""
from __future__ import annotations

from dataclasses import dataclass
import subprocess
from typing import Any, Collection, Sequence


@dataclass(frozen=True)
class CommandResult:
    node: str
    operation: str
    command: str
    returncode: int
    stdout: str
    stderr: str


class CommandError(RuntimeError):
    def __init__(self, result: CommandResult):
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic output"
        super().__init__(f"{result.node}: {result.operation} failed ({result.returncode}): {detail}")
        self.result = result


def _redact(parts: Sequence[str]) -> str:
    hidden = False
    rendered: list[str] = []
    for part in parts:
        if hidden:
            rendered.append("<redacted>")
            hidden = False
        elif part in {"--private-key", "PresharedKey", "PrivateKey"}:
            rendered.append(part)
            hidden = True
        else:
            rendered.append(part)
    return " ".join(rendered)


class LocalCommandRunner:
    def __init__(self, node_name: str):
        self.node_name = node_name

    def run(
        self,
        argv: Sequence[str],
        operation: str,
        accepted: Collection[int] = (0,),
        input_text: str | None = None,
        timeout_s: float = 15,
    ) -> CommandResult:
        completed = subprocess.run(
            list(argv), input=input_text, text=True, capture_output=True,
            check=False, timeout=timeout_s,
        )
        result = CommandResult(
            self.node_name, operation, _redact(argv), completed.returncode,
            completed.stdout or "", completed.stderr or "",
        )
        if result.returncode not in accepted:
            raise CommandError(result)
        return result


class NodeCommandRunner:
    """Checked equivalent for a Containernet node object."""

    def __init__(self, node: Any):
        self.node = node
        self.node_name = str(getattr(node, "name", "unknown-node"))

    def run(
        self, command: str, operation: str, accepted: Collection[int] = (0,),
        timeout_s: float = 30,
    ) -> CommandResult:
        process = self.node.popen(
            ["/bin/sh", "-c", command], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )
        try:
            stdout, stderr = process.communicate(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            raise CommandError(CommandResult(
                self.node_name, operation, command, 124, stdout or "", stderr or "timeout",
            ))
        result = CommandResult(
            self.node_name, operation, command, int(process.returncode), stdout or "", stderr or "",
        )
        if result.returncode not in accepted:
            raise CommandError(result)
        return result


class Transaction:
    """Run reversible operations and roll them back in reverse order on error."""

    def __init__(self) -> None:
        self._rollbacks: list[tuple[Sequence[str], str]] = []

    def apply(
        self, runner: LocalCommandRunner, action: Sequence[str], rollback: Sequence[str],
        operation: str,
    ) -> None:
        runner.run(action, operation)
        self._rollbacks.append((rollback, f"rollback {operation}"))

    def rollback(self, runner: LocalCommandRunner) -> list[str]:
        errors: list[str] = []
        for command, operation in reversed(self._rollbacks):
            try:
                runner.run(command, operation)
            except (CommandError, subprocess.TimeoutExpired) as exc:
                errors.append(str(exc))
        return errors


