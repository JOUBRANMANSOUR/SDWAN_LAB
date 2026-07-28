"""Bounded application-evidence cache; routing paths are never cached here."""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, replace
import time


AUTHORITATIVE_SOURCES = {"ndpi", "dns-association"}


@dataclass(frozen=True)
class EvidenceKey:
    destination: str
    transport: str
    port: int
    hostname: str


@dataclass(frozen=True)
class ApplicationEvidence:
    application: str
    category: str
    native_confidence: int
    source: str
    created_at: float
    expires_at: float
    catalog_version: int
    conflicts: int = 0

    @property
    def authoritative(self) -> bool:
        return (
            self.source in AUTHORITATIVE_SOURCES
            and self.application.lower() != "unknown"
        )


class ApplicationEvidenceCache:
    """LRU/TTL cache with conflict invalidation and CDN-safe lookup rules.

    Hostname is mandatory for a steering lookup. An address-only observation is
    useful telemetry, but it is deliberately not authoritative on shared IPs.
    """

    def __init__(self, maximum_entries: int, ttl_s: float):
        if maximum_entries <= 0 or ttl_s <= 0:
            raise ValueError("cache limits must be positive")
        self.maximum_entries = maximum_entries
        self.ttl_s = ttl_s
        self._items: OrderedDict[EvidenceKey, ApplicationEvidence] = OrderedDict()

    def remember(
        self, key: EvidenceKey, *, application: str, category: str,
        native_confidence: int, source: str, catalog_version: int,
        now: float | None = None,
    ) -> ApplicationEvidence | None:
        now = time.time() if now is None else now
        self.expire(now)
        if not key.hostname or source not in AUTHORITATIVE_SOURCES or application.lower() == "unknown":
            return None
        prior = self._items.get(key)
        conflicts = 0
        if prior and (prior.application != application or prior.category != category):
            conflicts = prior.conflicts + 1
            self._items.pop(key, None)
            # A conflicting identity must be re-observed; never overwrite it as
            # authoritative in the same operation.
            return replace(prior, conflicts=conflicts, expires_at=now)
        evidence = ApplicationEvidence(
            application, category, native_confidence, source, now,
            now + self.ttl_s, catalog_version, conflicts,
        )
        self._items[key] = evidence
        self._items.move_to_end(key)
        while len(self._items) > self.maximum_entries:
            self._items.popitem(last=False)
        return evidence

    def lookup(
        self, key: EvidenceKey, *, catalog_version: int,
        now: float | None = None,
    ) -> ApplicationEvidence | None:
        now = time.time() if now is None else now
        self.expire(now)
        if not key.hostname:
            return None
        item = self._items.get(key)
        if not item or item.catalog_version != catalog_version or not item.authoritative:
            return None
        self._items.move_to_end(key)
        return item

    def expire(self, now: float | None = None) -> int:
        now = time.time() if now is None else now
        expired = [key for key, value in self._items.items() if value.expires_at <= now]
        for key in expired:
            self._items.pop(key, None)
        return len(expired)

    def __len__(self) -> int:
        return len(self._items)
