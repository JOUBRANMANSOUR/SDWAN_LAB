"""Pure emergency route-slot remapping and recovery draining state."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import time


@dataclass
class RouteSlot:
    slot: str
    physical_path: str
    failed: bool = False
    emergency: bool = False
    drain_deadline: float | None = None


class LocalFailoverManager:
    def __init__(self, paths: tuple[str, ...], drain_timeout_s: float = 120):
        if drain_timeout_s <= 0:
            raise ValueError("drain timeout must be positive")
        self.paths = paths
        self.drain_timeout_s = drain_timeout_s
        self.slots = {path: RouteSlot(path, path) for path in paths}
        self.version = 0

    def blackout(self, failed_path: str, backup_path: str) -> RouteSlot:
        if failed_path not in self.slots or backup_path not in self.slots or failed_path == backup_path:
            raise ValueError("invalid blackout path mapping")
        slot = self.slots[failed_path]
        slot.physical_path = backup_path
        slot.failed = True
        slot.emergency = True
        slot.drain_deadline = None
        self.version += 1
        return RouteSlot(**asdict(slot))

    def begin_recovery(self, recovered_path: str, now: float | None = None) -> RouteSlot:
        if recovered_path not in self.slots:
            raise ValueError("unknown recovered path")
        slot = self.slots[recovered_path]
        slot.failed = False
        if slot.emergency:
            slot.drain_deadline = (time.monotonic() if now is None else now) + self.drain_timeout_s
        return RouteSlot(**asdict(slot))

    def tick(self, active_flows_by_slot: dict[str, int], now: float | None = None) -> list[RouteSlot]:
        """Pure-manager convenience: identify and commit ready restorations."""
        ready = self.ready_to_restore(active_flows_by_slot, now)
        return [self.complete_recovery(item.slot) for item in ready]

    def ready_to_restore(
        self, active_flows_by_slot: dict[str, int], now: float | None = None,
    ) -> list[RouteSlot]:
        now = time.monotonic() if now is None else now
        ready: list[RouteSlot] = []
        for name, slot in self.slots.items():
            if not slot.emergency or slot.failed or slot.drain_deadline is None:
                continue
            if active_flows_by_slot.get(name, 0) == 0 or now >= slot.drain_deadline:
                ready.append(RouteSlot(name, name, False, False, None))
        return ready

    def complete_recovery(self, recovered_path: str) -> RouteSlot:
        slot = self.slots[recovered_path]
        if slot.failed or not slot.emergency or slot.drain_deadline is None:
            raise ValueError("route slot is not ready for recovery completion")
        slot.physical_path = recovered_path
        slot.emergency = False
        slot.drain_deadline = None
        self.version += 1
        return RouteSlot(**asdict(slot))

    def snapshot(self) -> dict[str, object]:
        return {"version": self.version, "slots": {name: asdict(slot) for name, slot in self.slots.items()}}


