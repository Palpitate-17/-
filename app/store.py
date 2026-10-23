from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any


class ScanStore:
    """小型 SQLite 存储；每次操作独立连接，适合 API 后台任务。"""

    def __init__(self, database_path: str | Path):
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    api_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target_url TEXT NOT NULL,
                    request_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    pages_discovered INTEGER NOT NULL DEFAULT 0,
                    pages_scanned INTEGER NOT NULL DEFAULT 0,
                    findings_count INTEGER NOT NULL DEFAULT 0,
                    coverage_json TEXT NOT NULL DEFAULT '[]',
                    error_code TEXT,
                    error_message TEXT
                );
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    source_url TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    status TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    FOREIGN KEY(scan_id) REFERENCES scans(scan_id)
                );
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
                CREATE TABLE IF NOT EXISTS baselines (
                    url TEXT PRIMARY KEY,
                    version INTEGER NOT NULL,
                    record_json TEXT NOT NULL,
                    approved_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    event TEXT NOT NULL,
                    detail_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )

    def create_scan(self, record: dict[str, Any]) -> None:
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO scans (
                    scan_id, api_version, status, target_url, request_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    record["scan_id"], record["api_version"], record["status"],
                    record["target_url"], json.dumps(record["request"], ensure_ascii=False),
                    record["created_at"],
                ),
            )

    def update_scan(self, scan_id: str, **changes: Any) -> None:
        allowed = {
            "status", "started_at", "completed_at", "pages_discovered", "pages_scanned",
            "findings_count", "coverage_json", "error_code", "error_message",
        }
        unknown = set(changes) - allowed
        if unknown:
            raise ValueError(f"不允许更新扫描字段：{sorted(unknown)}")
        if not changes:
            return
        values: list[Any] = []
        assignments: list[str] = []
        for key, value in changes.items():
            assignments.append(f"{key} = ?")
            values.append(json.dumps(value, ensure_ascii=False) if key == "coverage_json" else value)
        values.append(scan_id)
        with self._connect() as connection:
            connection.execute(
                f"UPDATE scans SET {', '.join(assignments)} WHERE scan_id = ?", values
            )

    def get_scan(self, scan_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["request"] = json.loads(result.pop("request_json"))
        result["coverage"] = json.loads(result.pop("coverage_json"))
        return result

    def save_finding(self, payload: dict[str, Any]) -> None:
        stored = dict(payload)
        source_url = stored.pop("_source_url")
        finding_id = stored["finding_id"]
        scan_id = stored["scan_id"]
        fingerprint = stored["fingerprint"]
        status = stored["status"]
        first_seen = stored["first_seen"]
        last_seen = stored["last_seen"]
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO findings (
                    finding_id, scan_id, fingerprint, source_url, payload_json, status, first_seen, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id, scan_id, fingerprint, source_url,
                    json.dumps(stored, ensure_ascii=False), status, first_seen, last_seen,
                ),
            )

    def get_findings(self, scan_id: str) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload_json, status, last_seen FROM findings WHERE scan_id = ? ORDER BY finding_id",
                (scan_id,),
            ).fetchall()
        results = []
        for row in rows:
            payload = json.loads(row["payload_json"])
            payload["status"] = row["status"]
            payload["last_seen"] = row["last_seen"]
            results.append(payload)
        return results

    def get_finding(self, finding_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT source_url, payload_json, status, last_seen FROM findings WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        payload["_source_url"] = row["source_url"]
        payload["status"] = row["status"]
        payload["last_seen"] = row["last_seen"]
        return payload

    def get_latest_finding_by_fingerprint(self, fingerprint: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """SELECT payload_json, status, last_seen FROM findings
                WHERE fingerprint = ? ORDER BY last_seen DESC LIMIT 1""",
                (fingerprint,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["payload_json"])
        payload["status"] = row["status"]
        payload["last_seen"] = row["last_seen"]
        return payload

    def update_finding_status(self, finding_id: str, status: str, last_seen: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE findings SET status = ?, last_seen = ? WHERE finding_id = ?",
                (status, last_seen, finding_id),
            )

    def get_baseline(self, url: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT version, record_json, approved_at FROM baselines WHERE url = ?", (url,)
            ).fetchone()
        if row is None:
            return None
        return {
            "version": row["version"],
            "record": json.loads(row["record_json"]),
            "approved_at": row["approved_at"],
        }

    def save_initial_baseline(self, url: str, record: dict[str, Any], approved_at: str) -> bool:
        with self._connect() as connection:
            cursor = connection.execute(
                """INSERT OR IGNORE INTO baselines (url, version, record_json, approved_at)
                VALUES (?, 1, ?, ?)""",
                (url, json.dumps(record, ensure_ascii=False), approved_at),
            )
        return cursor.rowcount == 1

    def approve_baseline(self, url: str, record: dict[str, Any], approved_at: str) -> int:
        current = self.get_baseline(url)
        version = 1 if current is None else int(current["version"]) + 1
        with self._connect() as connection:
            connection.execute(
                """INSERT INTO baselines (url, version, record_json, approved_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(url) DO UPDATE SET version=excluded.version,
                    record_json=excluded.record_json, approved_at=excluded.approved_at""",
                (url, version, json.dumps(record, ensure_ascii=False), approved_at),
            )
        return version

    def audit(self, event: str, created_at: str, *, scan_id: str | None = None,
              detail: dict[str, Any] | None = None) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_logs (scan_id, event, detail_json, created_at) VALUES (?, ?, ?, ?)",
                (scan_id, event, json.dumps(detail or {}, ensure_ascii=False), created_at),
            )
