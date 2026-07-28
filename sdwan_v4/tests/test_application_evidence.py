from sdwan_v4.common.application_evidence import ApplicationEvidenceCache, EvidenceKey


def key(hostname: str = "example.test") -> EvidenceKey:
    return EvidenceKey("10.2.0.11", "tcp", 443, hostname)


def test_cache_stores_evidence_not_paths_and_expires() -> None:
    cache = ApplicationEvidenceCache(2, 10)
    item = cache.remember(
        key(), application="TLS", category="Web", native_confidence=3,
        source="ndpi", catalog_version=7, now=1,
    )
    assert item is not None and not hasattr(item, "path")
    assert cache.lookup(key(), catalog_version=7, now=5) == item
    assert cache.lookup(key(), catalog_version=7, now=12) is None


def test_address_only_and_unknown_evidence_are_not_authoritative() -> None:
    cache = ApplicationEvidenceCache(2, 10)
    assert cache.remember(
        key(""), application="TLS", category="Web", native_confidence=3,
        source="ndpi", catalog_version=1, now=1,
    ) is None
    assert cache.remember(
        key(), application="Unknown", category="Unspecified", native_confidence=0,
        source="port-hint", catalog_version=1, now=1,
    ) is None


def test_conflict_invalidates_prior_identity() -> None:
    cache = ApplicationEvidenceCache(2, 10)
    cache.remember(
        key(), application="TLS", category="Web", native_confidence=3,
        source="ndpi", catalog_version=1, now=1,
    )
    conflict = cache.remember(
        key(), application="QUIC", category="Web", native_confidence=3,
        source="ndpi", catalog_version=1, now=2,
    )
    assert conflict is not None and conflict.conflicts == 1
    assert cache.lookup(key(), catalog_version=1, now=3) is None
