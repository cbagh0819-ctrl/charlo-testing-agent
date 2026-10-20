"""
Unit and integration tests for Business Logic, State Machine & Workflow Integrity Testing Engine.
"""

import pytest
from charlo.core.models import ScanTarget, TargetType, CheckFinding, CheckStatus, Severity
from charlo.core.engine import ScanEngine
from charlo.analyzers.business_logic_tester import (
    BusinessLogicTester, BusinessWorkflowStep, BusinessLogicFlaw, BusinessLogicReport
)
from charlo.reporting.html_reporter import HTMLReporter


def test_business_workflow_step_dataclass():
    """Verify BusinessWorkflowStep properties and serialization."""
    step = BusinessWorkflowStep(
        step_number=1,
        name="Add Item to Cart",
        endpoint="/api/v1/cart/items",
        expected_state="CART_UPDATED",
        enforce_prerequisite="AUTHENTICATED_SESSION"
    )
    assert step.step_number == 1
    assert step.name == "Add Item to Cart"
    d = step.to_dict()
    assert d["endpoint"] == "/api/v1/cart/items"
    assert d["expected_state"] == "CART_UPDATED"


def test_business_logic_tester_web_target():
    """Verify BusinessLogicTester executes smoothly on web targets."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://example.com",
        display_name="Example Store"
    )
    report = BusinessLogicTester.run_tests(target)
    assert isinstance(report, BusinessLogicReport)
    assert report.target_name == "Example Store"
    assert report.total_workflows_evaluated >= 5
    assert report.total_checks >= 5
    assert len(report.workflows) >= 5
    assert len(report.flaws) >= 5
    assert 0.0 <= report.logic_integrity_score <= 100.0
    assert report.overall_status in ("LOGIC HARDENED", "DEFECTS REQUIRING ATTENTION", "CRITICAL TRANSACTION COMPROMISE")


def test_business_logic_flaw_structure():
    """Verify BusinessLogicFlaw contains PoC exploit payload and remediation pattern."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://api.retail.com",
        display_name="Retail API"
    )
    report = BusinessLogicTester.run_tests(target)
    for flaw in report.flaws:
        assert isinstance(flaw, BusinessLogicFlaw)
        assert flaw.flaw_id.startswith("LOGIC-")
        assert flaw.category in (
            "Price & Quantity Tampering",
            "Sequence & State Machine",
            "Privilege Escalation",
            "Concurrency Double-Spend",
            "MFA & Step-Up Bypass",
        )
        assert flaw.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
        assert flaw.status in ("PASSED", "DEFECT", "WARNING")
        assert len(flaw.title) > 0
        assert len(flaw.description) > 0
        assert len(flaw.impact) > 0
        assert len(flaw.remediation_pattern) > 0
        assert len(flaw.flawed_sequence_poc) > 0


def test_business_logic_pytest_suite_compilation():
    """Verify generated Pytest test suite script compiles as syntactically valid Python code."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://shop.enterprise.org",
        display_name="Enterprise Shop"
    )
    report = BusinessLogicTester.run_tests(target)
    pytest_code = report.pytest_logic_suite
    assert "import pytest" in pytest_code
    assert "def test_negative_quantity_rejection" in pytest_code
    assert "def test_mass_assignment_role_escalation" in pytest_code
    assert "def test_concurrent_double_spend_resilience" in pytest_code

    # Syntax compile check
    compiled = compile(pytest_code, "<string>", "exec")
    assert compiled is not None


def test_business_logic_copiable_markdown():
    """Verify generated executive deliverable markdown is formatted cleanly."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://banking.app",
        display_name="Banking App"
    )
    report = BusinessLogicTester.run_tests(target)
    md = report.copiable_client_markdown
    assert "CHARLO TESTING AGENT - PROFESSIONAL BUSINESS LOGIC AUDIT REPORT" in md
    assert "Banking App" in md
    assert "Logic Pass Score:" in md
    assert "AUDITED BUSINESS WORKFLOWS" in md
    assert "DETAILED DEFECT MATRIX" in md


def test_business_logic_html_reporter():
    """Verify HTMLReporter generates a full standalone report for business logic."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://fintech.io",
        display_name="Fintech Core"
    )
    report = BusinessLogicTester.run_tests(target)
    html = HTMLReporter.generate_business_logic_report(report.to_dict())
    assert "<!DOCTYPE html>" in html
    assert "Fintech Core" in html
    assert "BUSINESS LOGIC & TRANSACTION INTEGRITY" in html
    assert "Logic Score" in html
    assert "test_business_logic.py" in html


def test_business_logic_apk_exe_targets():
    """Verify BusinessLogicTester handles mobile (.apk) and desktop (.exe) targets."""
    apk_target = ScanTarget(
        target_type=TargetType.APK,
        target_path="C:/apps/wallet.apk",
        display_name="Wallet APK"
    )
    apk_report = BusinessLogicTester.run_tests(apk_target)
    assert apk_report.total_workflows_evaluated >= 5
    assert apk_report.logic_integrity_score > 0

    exe_target = ScanTarget(
        target_type=TargetType.EXE,
        target_path="C:/apps/pos_client.exe",
        display_name="POS Client"
    )
    exe_report = BusinessLogicTester.run_tests(exe_target)
    assert exe_report.total_workflows_evaluated >= 5


def test_scan_engine_e2e_logic_integration():
    """Verify ScanEngine executes business logic audit step and saves metadata."""
    engine = ScanEngine()
    result = engine.run_scan("https://example.com")
    assert result.target is not None
    assert "business_logic_report" in result.target.metadata
    logic_data = result.target.metadata["business_logic_report"]
    assert logic_data["total_workflows_evaluated"] >= 5
    assert logic_data["logic_integrity_score"] > 0
    assert len(logic_data["flaws"]) >= 5
