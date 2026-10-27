"""Finds store — sqlite-backed persistence for scans and findings."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from agentpoi_scan.findings.model import Finding
from agentpoi_scan.findings.risk_score import repo_risk_score

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    created_at TEXT NOT NULL,
    risk_vulnerable REAL NOT NULL,
    risk_malicious REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    fingerprint TEXT NOT NULL,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    payload TEXT NOT NULL,
    PRIMARY KEY (fingerprint, scan_id)
);
"""


class ScanStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.path))
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- writes ----------------------------------------------------------------
    def add_scan(self, repo: str, commit_sha: str, findings: Iterable[Finding]) -> int:
        findings = list(findings)
        risk = repo_risk_score(findings)
        cursor = self._conn.execute(
            "INSERT INTO scans (repo, commit_sha, created_at, risk_vulnerable, risk_malicious) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                repo,
                commit_sha,
                datetime.now(timezone.utc).isoformat(),
                risk["vulnerable"],
                risk["malicious"],
            ),
        )
        scan_id = int(cursor.lastrowid)
        for finding in findings:
            self._conn.execute(
                "INSERT OR REPLACE INTO findings (fingerprint, scan_id, payload) VALUES (?, ?, ?)",
                (finding.fingerprint, scan_id, json.dumps(finding.to_dict())),
            )
        self._conn.commit()
        return scan_id

    # -- reads -----------------------------------------------------------------
    def get_scan(self, scan_id: int) -> Optional[Dict]:
        row = self._conn.execute(
            "SELECT id, repo, commit_sha, created_at, risk_vulnerable, risk_malicious "
            "FROM scans WHERE id = ?",
            (scan_id,),
        ).fetchone()
        if row is None:
            return None
        return {
            "id": row[0],
            "repo": row[1],
            "commit_sha": row[2],
            "created_at": row[3],
            "risk": {"vulnerable": row[4], "malicious": row[5]},
        }

    def list_findings(
        self,
        scan_id: int,
        severity: Optional[str] = None,
        category: Optional[str] = None,
    ) -> List[Finding]:
        query = "SELECT payload FROM findings WHERE scan_id = ?"
        params: list = [scan_id]
        if severity:
            query += " AND json_extract(payload, '$.severity') = ?"
            params.append(severity)
        if category:
            query += " AND json_extract(payload, '$.category') = ?"
            params.append(category)
        rows = self._conn.execute(query, params).fetchall()
        return [Finding.from_dict(json.loads(row[0])) for row in rows]

    def latest_scan(self) -> Optional[Dict]:
        row = self._conn.execute("SELECT MAX(id) FROM scans").fetchone()
        return self.get_scan(row[0]) if row and row[0] else None
