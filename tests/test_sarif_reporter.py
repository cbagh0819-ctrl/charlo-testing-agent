"""
Unit tests for Universal OASIS SARIF 2.1.0 Exporter.
"""

import json
import pytest
from charlo.core.models import (
    ScanResult, ScanTarget, ScanMetrics, CheckFinding,
    TargetType, ScanLevel, Severity, CheckStatus
)
from charlo.reporting.sarif_reporter import SarifReporter


@pytest.fixture
def sample_scan_result():
    target = ScanTarget(
        target_path="https://api.pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC Portal"
    )
    metrics = ScanMetrics(
        security_score=82.5,
        posture_grade="B",
        total_checks=2,
        passed=1,
        failed=1,
        warnings=0
    )
    finding_fail = CheckFinding(
        check_id="WEB-INJ-001",
        check_name="SQL Injection Check",
        target_type=TargetType.WEB,
        category="Injection",
        status=CheckStatus.FAILED,
        severity=Severity.CRITICAL,
        title="SQL Injection Vulnerability",
        description="SQL injection flaw in search parameters.",
        affected_component="/api/v1/search",
        evidence="Unsanitized query parameters in /search",
        impact="Data breach",
        remediation="Use parameterized database queries.",
        standards=["OWASP Top 10 A03", "CWE-89"]
    )
    finding_pass = CheckFinding(
        check_id="WEB-TLS-001",
        check_name="TLS Protocol Check",
        target_type=TargetType.WEB,
        category="Transport",
        status=CheckStatus.PASSED,
        severity=Severity.LOW,
        title="Valid TLS 1.3 Encryption",
        description="TLS 1.3 encryption is active.",
        affected_component="port 443",
        evidence="TLS 1.3 negotiated successfully",
        impact="None",
        remediation="None"
    )
    return ScanResult(
        target=target,
        level=ScanLevel.ADVANCED,
        start_time="2026-10-20T10:00:00",
        end_time="2026-10-20T10:00:03",
        findings=[finding_fail, finding_pass],
        metrics=metrics
    )


def test_sarif_schema_and_version(sample_scan_result):
    """Verify SARIF report adheres to OASIS 2.1.0 standard schema."""
    sarif_json = SarifReporter.generate(sample_scan_result)
    data = json.loads(sarif_json)

    assert data["version"] == "2.1.0"
    assert "sarif-schema-2.1.0.json" in data["$schema"]
    assert len(data["runs"]) == 1

    driver = data["runs"][0]["tool"]["driver"]
    assert driver["name"] == "CHARLO Testing Agent"
    assert driver["semanticVersion"] == "2.4.0"


def test_sarif_rules_and_results_mapping(sample_scan_result):
    """Verify failed/warning findings are mapped to SARIF rules and results."""
    sarif_json = SarifReporter.generate(sample_scan_result)
    data = json.loads(sarif_json)

    run = data["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    results = run["results"]

    # All evaluated checks register rules, but only defects generate results
    assert len(rules) == 2
    assert rules[0]["id"] == "WEB-INJ-001"
    assert rules[0]["name"] == "SQL_Injection_Check"

    assert len(results) == 1
    res = results[0]
    assert res["ruleId"] == "WEB-INJ-001"
    assert res["level"] == "error"  # Critical maps to error
    assert "SQL injection flaw" in res["message"]["text"]


def test_sarif_export_file(sample_scan_result, tmp_path):
    """Verify file output writes valid SARIF JSON to disk."""
    out_file = tmp_path / "audit.sarif"
    SarifReporter.export_file(sample_scan_result, str(out_file))

    assert out_file.exists()
    content = json.loads(out_file.read_text(encoding="utf-8"))
    assert content["version"] == "2.1.0"
