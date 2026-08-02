"""Read-only service database access and isolated management audit storage."""
from __future__ import annotations

import json, sqlite3
from pathlib import Path
from typing import Any

def _ro(path: Path) -> sqlite3.Connection | None:
    if not path.is_file(): return None
    connection = sqlite3.connect("file:" + str(path) + "?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection

class ReadOnlyState:
    def __init__(self, policy_db: Path, ztp_db: Path): self.policy_db, self.ztp_db = policy_db, ztp_db
    def rows(self, source: str, query: str, parameters: tuple = ()) -> list[dict[str, Any]]:
        path = self.policy_db if source == "policy" else self.ztp_db
        db = _ro(path)
        if db is None: return []
        try: return [dict(row) for row in db.execute(query, parameters)]
        finally: db.close()

class AuditStore:
    def __init__(self, state_dir: Path):
        state_dir.mkdir(parents=True, exist_ok=True); self.path = state_dir / "management.db"
        with sqlite3.connect(str(self.path)) as db:
            db.execute("CREATE TABLE IF NOT EXISTS audit_events (id INTEGER PRIMARY KEY, created_at TEXT DEFAULT CURRENT_TIMESTAMP, actor TEXT, action TEXT, target TEXT, outcome TEXT, detail TEXT)")
    def add(self, actor: str, action: str, target: str, outcome: str, detail: str = "") -> None:
        with sqlite3.connect(str(self.path)) as db: db.execute("INSERT INTO audit_events(actor,action,target,outcome,detail) VALUES(?,?,?,?,?)", (actor,action,target,outcome,detail[:512]))
    def list(self) -> list[dict[str, Any]]:
        with sqlite3.connect(str(self.path)) as db:
            db.row_factory = sqlite3.Row; return [dict(row) for row in db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT 200")]
