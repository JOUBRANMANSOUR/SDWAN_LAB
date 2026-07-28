from hashlib import sha256
from pathlib import Path


EXPECTED = "AB381147C345504121D1B6ECE933F5DB585394C496AD4345F42D781F40010E50"


def test_v3_manifest_is_unchanged() -> None:
    root = Path(__file__).resolve().parents[2] / "sdwan_v3"
    rows = []
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        rows.append(f"{sha256(path.read_bytes()).hexdigest().upper()}  {path.relative_to(root).as_posix()}")
    assert len(rows) == 64
    assert sha256("\n".join(rows).encode()).hexdigest().upper() == EXPECTED
