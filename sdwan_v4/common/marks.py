"""Stable packet/conntrack mark ABI for SD-WAN v4.

The terminal bit means inline inspection stopped. It does not mean that nDPI
identified the application; userspace retains CLASSIFIED versus
TERMINAL_UNKNOWN as separate outcomes.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FlowMarkStage(str, Enum):
    UNKNOWN = "unknown"
    PROVISIONAL = "provisional"
    TERMINAL = "terminal"


@dataclass(frozen=True)
class MarkLayout:
    """Low byte is a route slot; upper bits describe flow state.

    A route slot normally maps to its same-named transport, but the Edge may
    remap that table during blackout so existing conntrack marks keep working.
    """

    path_mask: int = 0x0FF
    terminal_bit: int = 0x100
    provisional_bit: int = 0x200
    emergency_bit: int = 0x400

    @property
    def state_mask(self) -> int:
        return self.terminal_bit | self.provisional_bit | self.emergency_bit

    @property
    def combined_mask(self) -> int:
        return self.path_mask | self.state_mask

    def validate(self, path_marks: dict[str, int]) -> None:
        values = list(path_marks.values())
        if not values or len(values) != len(set(values)):
            raise ValueError("path marks must be nonempty and unique")
        if any(value <= 0 or value & ~self.path_mask for value in values):
            raise ValueError("every path mark must fit entirely inside path_mask")
        bits = (self.terminal_bit, self.provisional_bit, self.emergency_bit)
        if any(bit <= 0 or bit & (bit - 1) for bit in bits):
            raise ValueError("classification/emergency values must be individual bits")
        if len(set(bits)) != len(bits) or self.path_mask & self.state_mask:
            raise ValueError("path and state mark fields must not overlap")

    def encode(self, path_mark: int, stage: FlowMarkStage, emergency: bool = False) -> int:
        if path_mark <= 0 or path_mark & ~self.path_mask:
            raise ValueError("path mark is outside path_mask")
        value = path_mark
        if stage is FlowMarkStage.PROVISIONAL:
            value |= self.provisional_bit
        elif stage is FlowMarkStage.TERMINAL:
            value |= self.terminal_bit
        if emergency:
            value |= self.emergency_bit
        return value

    def path_value(self, mark: int) -> int:
        return mark & self.path_mask

    def stage(self, mark: int) -> FlowMarkStage:
        if mark & self.terminal_bit:
            return FlowMarkStage.TERMINAL
        if mark & self.provisional_bit:
            return FlowMarkStage.PROVISIONAL
        return FlowMarkStage.UNKNOWN

    def is_emergency(self, mark: int) -> bool:
        return bool(mark & self.emergency_bit)
