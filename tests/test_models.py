"""
Unit tests for CHARLO Core Models and Taxonomy.
"""

import pytest
from charlo.core.models import (
    TargetType,
    ScanLevel,
    Severity,
    CheckStatus,
    CheckFinding,
    ScanTarget,
    ScanMetrics,
    ScanResult,
)


def test_target_type_detection():
    assert TargetType.from_string("test.apk") == TargetType.APK
    assert TargetType.from_string("target.exe") == TargetType.EXE
    assert TargetType.from_string("https://example.com") == TargetType.WEB


def test_scan_level_ranks():
    assert ScanLevel.BASIC.rank < ScanLevel.INTERMEDIATE.rank
    assert ScanLevel.INTERMEDIATE.rank < ScanLevel.ADVANCED.rank


def test_severity_weights():
    assert Severity.CRITICAL.score_weight > Severity.HIGH.score_weight
    assert Severity.HIGH.score_weight > Severity.MEDIUM.score_weight
    assert Severity.MEDIUM.score_weight > Severity.LOW.score_weight


def test_finding_serialization():
    finding = CheckFinding(
        check_id="EXE-001",
        check_name="ASLR Check",
        target_type=TargetType.EXE,
        category="Mitigations",
        status=CheckStatus.FAILED,
        severity=Severity.HIGH,
        title="ASLR Disabled",
        description="Dynamic base flag missing.",
        affected_component="PE Header",
        evidence="DYNAMIC_BASE flag is 0",
        impact="Predictable memory offsets.",
        remediation="Enable /DYNAMICBASE",
        standards=["CWE-119"],
    )

    d = finding.to_dict()
    assert d["check_id"] == "EXE-001"
    assert d["severity"] == "high"
    assert d["status"] == "failed"

    recovered = CheckFinding.from_dict(d)
    assert recovered.check_id == finding.check_id
    assert recovered.severity == Severity.HIGH
    assert recovered.status == CheckStatus.FAILED


def test_string_coercion_robustness():
    # Test that raw strings (such as those returned by Qt QVariant) cleanly coerce
    assert TargetType.from_string("apk") == TargetType.APK
    assert TargetType.from_string("exe") == TargetType.EXE
    assert TargetType.from_string("web") == TargetType.WEB

    assert ScanLevel.from_string("basic") == ScanLevel.BASIC
    assert ScanLevel.from_string("intermediate") == ScanLevel.INTERMEDIATE
    assert ScanLevel.from_string("advanced") == ScanLevel.ADVANCED

