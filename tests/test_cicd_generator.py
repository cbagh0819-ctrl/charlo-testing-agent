"""
Unit and integration tests for CHARLO CI/CD Automation & Quality Gate Generator.

Tests:
- Quality Gate evaluation with passing, breaching, and custom thresholds.
- Universal JUnit XML test deliverable generation and XML schema conformance.
- GitHub Actions workflow YAML generation (.github/workflows/quality_gate.yml).
- GitLab CI/CD pipeline YAML generation (.gitlab-ci.yml).
- Jenkins Declarative Pipeline script generation (Jenkinsfile).
- Standalone HTML CI/CD report generation via HTMLReporter.
- ScanEngine integration verifying metadata["cicd_report"] persistence.
"""

import xml.etree.ElementTree as ET
import pytest
from charlo.core.models import TargetType, ScanTarget, ScanResult, ScanMetrics, CheckFinding, CheckStatus, Severity, ScanLevel
from charlo.core.engine import ScanEngine
from charlo.analyzers.cicd_generator import (
    CiCdGenerator, QualityGateRule, QualityGateResult, CiCdPipelineReport
)
from charlo.reporting.html_reporter import HTMLReporter


def test_quality_gate_clean_pass():
    """Verify Quality Gate passes when all metrics satisfy threshold criteria."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    findings = [
        CheckFinding(
            check_id="WEB-001",
            check_name="HTTPS Enforcement",
            target_type=TargetType.WEB,
            category="Security",
            severity=Severity.INFO,
            status=CheckStatus.PASSED,
            title="HTTPS Enforced",
            description="HTTPS active",
            affected_component="Web Server",
            evidence="200 OK via HTTPS",
            impact="None",
            remediation="None",
        )
    ]
    metrics = ScanMetrics(
        total_checks=1,
        passed=1,
        failed=0,
        security_score=95.0,
    )
    result = ScanResult(
        target=target,
        level=ScanLevel.BASIC,
        findings=findings,
        metrics=metrics,
    )

    rule = QualityGateRule(
        max_critical_findings=0,
        max_high_findings=0,
        min_overall_score=80.0
    )

    gate = CiCdGenerator.evaluate_quality_gate(result, rule)
    assert gate.passed is True
    assert gate.status == "GATE PASSED"
    assert gate.total_violations == 0
    assert len(gate.violation_details) > 0


def test_quality_gate_breach_on_critical_and_score():
    """Verify Quality Gate flags violations when criticals or score thresholds fail."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://vulnerable-site.com",
        display_name="vulnerable-site.com"
    )
    findings = [
        CheckFinding(
            check_id="WEB-003",
            check_name="SQL Injection",
            target_type=TargetType.WEB,
            category="Injection",
            severity=Severity.CRITICAL,
            status=CheckStatus.FAILED,
            title="SQL Injection Detected",
            description="Union-based SQLi in search param",
            affected_component="/api/v1/search",
            evidence="SELECT * FROM users",
            impact="Full database takeover",
            remediation="Use prepared statements",
        ),
        CheckFinding(
            check_id="WEB-004",
            check_name="Remote Code Execution",
            target_type=TargetType.WEB,
            category="RCE",
            severity=Severity.HIGH,
            status=CheckStatus.FAILED,
            title="Insecure Deserialization",
            description="Arbitrary code execution",
            affected_component="/api/v1/upload",
            evidence="os.system() invoked",
            impact="Host compromise",
            remediation="Sanitize payloads",
        )
    ]
    metrics = ScanMetrics(
        total_checks=2,
        passed=0,
        failed=2,
        security_score=40.0,
    )
    result = ScanResult(
        target=target,
        level=ScanLevel.ADVANCED,
        findings=findings,
        metrics=metrics,
    )

    rule = QualityGateRule(
        max_critical_findings=0,
        max_high_findings=0,
        min_overall_score=75.0
    )

    gate = CiCdGenerator.evaluate_quality_gate(result, rule)
    assert gate.passed is False
    assert gate.status == "GATE BREACHED"
    assert gate.total_violations >= 2
    assert any("Critical" in v for v in gate.violation_details)
    assert any("Score" in v for v in gate.violation_details)
    assert len(gate.remediation_advice) >= 2


def test_junit_xml_generation_and_schema_validity():
    """Verify that generated JUnit XML parses cleanly into standard XML tree."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    findings = [
        CheckFinding(
            check_id="WEB-001",
            check_name="HTTPS Check",
            target_type=TargetType.WEB,
            category="Transport",
            severity=Severity.INFO,
            status=CheckStatus.PASSED,
            title="HTTPS Enforced",
            description="HTTPS active",
            affected_component="Web Server",
            evidence="HTTPS 200",
            impact="None",
            remediation="None",
        ),
        CheckFinding(
            check_id="WEB-002",
            check_name="HSTS Check",
            target_type=TargetType.WEB,
            category="Headers",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAILED,
            title="Missing HSTS Header",
            description="Strict-Transport-Security missing",
            affected_component="HTTP Response Headers",
            evidence="Header missing",
            impact="SSL Strip attack possible",
            remediation="Configure max-age=31536000",
        )
    ]
    result = ScanResult(
        target=target,
        level=ScanLevel.BASIC,
        findings=findings,
        metrics=ScanMetrics(total_checks=2, passed=1, failed=1, security_score=85.0),
    )

    xml_text = CiCdGenerator.generate_junit_xml(result)
    assert "<?xml" in xml_text
    assert "<testsuites" in xml_text
    assert "<testsuite" in xml_text
    assert "<testcase" in xml_text
    assert "<failure" in xml_text

    # Verify well-formed XML syntax via ElementTree
    root = ET.fromstring(xml_text)
    assert root.tag == "testsuites"
    suites = list(root)
    assert len(suites) >= 1
    testcases = list(suites[0])
    assert len(testcases) == 2


def test_pipeline_files_generation():
    """Verify GitHub Actions, GitLab CI, and Jenkinsfile scripts generate properly."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    rule = QualityGateRule()

    # GitHub Actions
    gh = CiCdGenerator.generate_github_actions(target, rule)
    assert "name: CHARLO" in gh
    assert "actions/checkout@v4" in gh
    assert "actions/setup-python@v5" in gh
    assert "python main.py --cli" in gh
    assert "https://pmec.ac.in" in gh

    # GitLab CI
    gl = CiCdGenerator.generate_gitlab_ci(target, rule)
    assert "stages:" in gl
    assert "security-audit" in gl
    assert "quality-gate" in gl
    assert "python:3.12-slim" in gl

    # Jenkinsfile
    jk = CiCdGenerator.generate_jenkinsfile(target, rule)
    assert "pipeline {" in jk
    assert "agent any" in jk
    assert "stage('Execute CHARLO Automated Audit')" in jk
    assert "stage('Quality Gate & SLA Enforcement')" in jk


def test_html_reporter_generate_cicd_report():
    """Verify HTMLReporter generates standalone CI/CD Quality Gate report."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://pmec.ac.in",
        display_name="pmec.ac.in"
    )
    report = CiCdGenerator.run_pipeline_generation(target, None, None)
    html = HTMLReporter.generate_cicd_report(report)

    assert "<!DOCTYPE html>" in html
    assert "CI/CD DEVOPS QUALITY GATE" in html
    assert "Quality Gate Status" in html
    assert "Overall Health Score" in html
    assert "GitHub Actions Workflow" in html
    assert "GitLab CI/CD Pipeline" in html
    assert "Jenkins Declarative Pipeline" in html
    assert "Universal JUnit XML Test Deliverable" in html


def test_scan_engine_cicd_integration():
    """Verify ScanEngine.run_scan populates metadata['cicd_report']."""
    engine = ScanEngine()
    result = engine.run_scan(
        target_input="https://example.com",
        target_type=TargetType.WEB,
        level=ScanLevel.BASIC
    )

    assert "cicd_report" in result.target.metadata
    cicd_data = result.target.metadata["cicd_report"]
    assert isinstance(cicd_data, dict)
    assert "gate_result" in cicd_data
    assert "github_actions_yaml" in cicd_data
    assert "junit_xml_content" in cicd_data
    assert len(cicd_data["github_actions_yaml"]) > 50
    assert len(cicd_data["junit_xml_content"]) > 50
