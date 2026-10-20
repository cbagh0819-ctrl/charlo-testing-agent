"""
Unit tests for SQLite Storage.
"""

import tempfile
import os
from charlo.core.models import (
    ScanResult, ScanTarget, TargetType, ScanLevel, ScanMetrics, CheckFinding, CheckStatus, Severity
)
from charlo.database.storage import ScanDatabase


def test_save_and_retrieve_scan():
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tmp:
        db_path = tmp.name

    try:
        db = ScanDatabase(db_path)
        target = ScanTarget(
            target_type=TargetType.EXE,
            target_path="C:\\sample\\test.exe",
            display_name="test.exe",
            size_bytes=1024,
            sha256="abc123456",
        )
        finding = CheckFinding(
            check_id="EXE-001",
            check_name="ASLR",
            target_type=TargetType.EXE,
            category="Mitigations",
            status=CheckStatus.PASSED,
            severity=Severity.HIGH,
            title="ASLR Enabled",
            description="",
            affected_component="PE Header",
            evidence="OK",
            impact="",
            remediation="",
        )
        result = ScanResult(
            target=target,
            level=ScanLevel.BASIC,
            start_time="2026-10-20T00:00:00",
            duration_seconds=1.23,
            findings=[finding],
            metrics=ScanMetrics(total_checks=1, passed=1, security_score=100.0, posture_grade="A+"),
        )

        db.save_scan(result)
        all_scans = db.get_all_scans()
        assert len(all_scans) == 1
        assert all_scans[0]["display_name"] == "test.exe"

        loaded = db.get_scan_by_id(result.scan_id)
        assert loaded is not None
        assert loaded.scan_id == result.scan_id
        assert len(loaded.findings) == 1
        assert loaded.findings[0].check_id == "EXE-001"

    finally:
        if os.path.exists(db_path):
            os.remove(db_path)
