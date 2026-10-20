"""
Unit tests for Risk Scoring Engine.
"""

from charlo.core.models import CheckFinding, CheckStatus, Severity, TargetType
from charlo.core.scoring import RiskCalculator


def test_clean_score():
    findings = [
        CheckFinding(
            check_id="EXE-001",
            check_name="Check 1",
            target_type=TargetType.EXE,
            category="General",
            status=CheckStatus.PASSED,
            severity=Severity.HIGH,
            title="Passed",
            description="",
            affected_component="",
            evidence="",
            impact="",
            remediation="",
        )
    ]
    metrics = RiskCalculator.calculate_metrics(findings)
    assert metrics.security_score == 100.0
    assert metrics.posture_grade == "A+"
    assert metrics.passed == 1
    assert metrics.failed == 0


def test_critical_deduction():
    findings = [
        CheckFinding(
            check_id="EXE-004",
            check_name="W^X Section",
            target_type=TargetType.EXE,
            category="Memory",
            status=CheckStatus.FAILED,
            severity=Severity.CRITICAL,
            title="W^X Section Flagged",
            description="",
            affected_component="",
            evidence="",
            impact="",
            remediation="",
        )
    ]
    metrics = RiskCalculator.calculate_metrics(findings)
    # Critical should deduct score and cap grade at D or F
    assert metrics.critical_count == 1
    assert metrics.security_score <= 90.0
    assert metrics.posture_grade in ("D", "F")
