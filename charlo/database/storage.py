"""
SQLite Persistence Storage for CHARLO Testing Agent.
Maintains audit logs, scan history, and findings.
"""

import os
import json
import sqlite3
from typing import List, Dict, Any, Optional
from ..core.models import ScanResult


class ScanDatabase:
    """
    Manages local SQLite database for scan history and findings.
    """

    DEFAULT_DB_PATH = os.path.join(
        os.path.expanduser("~"), ".charlo", "charlo_history.db"
    )

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DEFAULT_DB_PATH
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        scan_id TEXT PRIMARY KEY,
                        target_type TEXT NOT NULL,
                        target_path TEXT NOT NULL,
                        display_name TEXT NOT NULL,
                        level TEXT NOT NULL,
                        security_score REAL NOT NULL,
                        posture_grade TEXT NOT NULL,
                        critical_count INTEGER DEFAULT 0,
                        high_count INTEGER DEFAULT 0,
                        medium_count INTEGER DEFAULT 0,
                        low_count INTEGER DEFAULT 0,
                        passed_count INTEGER DEFAULT 0,
                        start_time TEXT NOT NULL,
                        duration_seconds REAL DEFAULT 0.0,
                        raw_json TEXT NOT NULL
                    )
                """)

                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id TEXT NOT NULL,
                        check_id TEXT NOT NULL,
                        check_name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        status TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        affected_component TEXT,
                        evidence TEXT,
                        remediation TEXT,
                        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
                    )
                """)

                cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(start_time DESC)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
        finally:
            conn.close()

    def save_scan(self, result: ScanResult):
        target = result.target
        raw_json_str = json.dumps(result.to_dict())

        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO scans (
                        scan_id, target_type, target_path, display_name, level,
                        security_score, posture_grade, critical_count, high_count,
                        medium_count, low_count, passed_count, start_time,
                        duration_seconds, raw_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    result.scan_id,
                    target.target_type.value if target else "unknown",
                    target.target_path if target else "unknown",
                    target.display_name if target else "unknown",
                    result.level.value,
                    result.metrics.security_score,
                    result.metrics.posture_grade,
                    result.metrics.critical_count,
                    result.metrics.high_count,
                    result.metrics.medium_count,
                    result.metrics.low_count,
                    result.metrics.passed,
                    result.start_time,
                    result.duration_seconds,
                    raw_json_str,
                ))

                # Insert findings
                cursor.execute("DELETE FROM findings WHERE scan_id = ?", (result.scan_id,))
                for f in result.findings:
                    cursor.execute("""
                        INSERT INTO findings (
                            scan_id, check_id, check_name, category, status,
                            severity, title, affected_component, evidence, remediation
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        result.scan_id,
                        f.check_id,
                        f.check_name,
                        f.category,
                        f.status.value,
                        f.severity.value,
                        f.title,
                        f.affected_component,
                        str(f.evidence),
                        f.remediation,
                    ))
        finally:
            conn.close()

    def get_all_scans(self) -> List[Dict[str, Any]]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT scan_id, target_type, display_name, level, security_score,
                       posture_grade, critical_count, high_count, medium_count,
                       low_count, passed_count, start_time, duration_seconds
                FROM scans
                ORDER BY start_time DESC
            """)
            rows = cursor.fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()

    def get_scan_by_id(self, scan_id: str) -> Optional[ScanResult]:
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT raw_json FROM scans WHERE scan_id = ?", (scan_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = json.loads(row["raw_json"])
            return ScanResult.from_dict(data)
        finally:
            conn.close()

    def delete_scan(self, scan_id: str):
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
                cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        finally:
            conn.close()
