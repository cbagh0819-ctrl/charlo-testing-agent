"""
Unit and integration tests for Automated Accessibility Audit & Assistive Technology Matrix (WCAG 2.2 / VPAT).
"""

import pytest
from charlo.core.models import ScanTarget, TargetType, CheckFinding, CheckStatus, Severity
from charlo.core.engine import ScanEngine
from charlo.analyzers.accessibility_tester import (
    AccessibilityTester, AccessibilityCriterionDefect, AriaLandmark, AccessibilityMetrics, AccessibilityReport
)
from charlo.reporting.html_reporter import HTMLReporter


def test_accessibility_metrics_dataclass():
    """Verify AccessibilityMetrics properties and serialization."""
    metrics = AccessibilityMetrics(
        wcag_score=85.0,
        conformance_status="PARTIALLY SUPPORTS (WCAG 2.2 AA)",
        total_criteria_checked=10,
        passed_criteria=7,
        defects_count=2,
        warnings_count=1,
        contrast_violations=1,
        missing_labels=1,
        keyboard_traps=0,
        missing_alt_tags=0,
    )
    d = metrics.to_dict()
    assert d["wcag_score"] == 85.0
    assert d["conformance_status"] == "PARTIALLY SUPPORTS (WCAG 2.2 AA)"
    assert d["total_criteria_checked"] == 10
    assert d["contrast_violations"] == 1


def test_aria_landmark_dataclass():
    """Verify AriaLandmark properties and serialization."""
    lm = AriaLandmark(
        role="navigation",
        element="<nav aria-label='Main'>",
        accessible_name="Main",
        status="VALID"
    )
    d = lm.to_dict()
    assert d["role"] == "navigation"
    assert d["element"] == "<nav aria-label='Main'>"
    assert d["accessible_name"] == "Main"
    assert d["status"] == "VALID"


def test_accessibility_tester_web_target():
    """Verify AccessibilityTester on web target evaluates WCAG 2.2 criteria and landmarks."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://accessibility.example.org",
        display_name="Accessible Portal"
    )
    report = AccessibilityTester.run_tests(target)
    assert isinstance(report, AccessibilityReport)
    assert report.target_name == "Accessible Portal"
    assert report.target_type == "web"
    assert len(report.landmarks) >= 3
    assert report.metrics.total_criteria_checked >= 6
    assert any("Contrast" in d.title or "1.4.3" in d.wcag_sc for d in report.defects)
    assert any("Focus" in d.title or "2.4.7" in d.wcag_sc for d in report.defects)
    assert any("Skip" in d.title or "2.4.1" in d.wcag_sc for d in report.defects)


def test_accessibility_tester_apk_target():
    """Verify AccessibilityTester on Android .apk targets checks contentDescription and touch targets."""
    target = ScanTarget(
        target_type=TargetType.APK,
        target_path="C:/builds/accessible_app.apk",
        display_name="Accessible APK"
    )
    report = AccessibilityTester.run_tests(target)
    assert isinstance(report, AccessibilityReport)
    assert report.target_type == "apk"
    assert report.metrics.total_criteria_checked >= 3
    assert any("contentDescription" in d.title for d in report.defects)
    assert any("Target Size" in d.title or "Touch" in d.title for d in report.defects)


def test_accessibility_tester_exe_target():
    """Verify AccessibilityTester on desktop .exe targets checks UI Automation (UIA) properties."""
    target = ScanTarget(
        target_type=TargetType.EXE,
        target_path="C:/tools/accessible_desktop.exe",
        display_name="Accessible Desktop"
    )
    report = AccessibilityTester.run_tests(target)
    assert isinstance(report, AccessibilityReport)
    assert report.target_type == "exe"
    assert report.metrics.total_criteria_checked >= 2
    assert any("UI Automation" in d.title or "UIA" in d.title for d in report.defects)


def test_axe_playwright_suite_compilation():
    """Verify generated Axe-core / Playwright test suite compiles as valid Python syntax."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://shop.enterprise.org",
        display_name="Enterprise Shop"
    )
    report = AccessibilityTester.run_tests(target)
    script = report.axe_playwright_suite
    assert "axe-core" in script
    assert "sync_playwright" in script
    assert "test_axe_core_wcag_22_aa_compliance" in script

    # Syntax compile check
    compiled = compile(script, "<string>", "exec")
    assert compiled is not None


def test_vpat_copiable_markdown():
    """Verify generated official VPAT 2.4 markdown deliverable is formatted cleanly."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://gov.services.org",
        display_name="Gov Services"
    )
    report = AccessibilityTester.run_tests(target)
    md = report.copiable_vpat_markdown
    assert "ACCESSIBILITY CONFORMANCE REPORT (VPAT 2.4)" in md
    assert "Gov Services" in md
    assert "W3C WCAG 2.2 Level A & Level AA" in md
    assert "ARIA ACCESSIBILITY TREE" in md
    assert "DETAILED CONFORMANCE MATRIX" in md


def test_accessibility_html_reporter():
    """Verify HTMLReporter generates a full standalone report for WCAG & VPAT."""
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://bank.security.com",
        display_name="Bank Security"
    )
    report = AccessibilityTester.run_tests(target)
    html = HTMLReporter.generate_accessibility_report(report.to_dict())
    assert "<!DOCTYPE html>" in html
    assert "Bank Security" in html
    assert "WCAG 2.2 & SECTION 508 AUDIT" in html
    assert "WCAG Score" in html
    assert "WAI-ARIA Accessibility Tree & Landmark Telemetry" in html


def test_scan_engine_e2e_a11y_integration():
    """Verify ScanEngine executes accessibility audit step and stores metadata."""
    engine = ScanEngine()
    result = engine.run_scan("https://example.com")
    assert result.target is not None
    assert "accessibility_report" in result.target.metadata
    a11y_data = result.target.metadata["accessibility_report"]
    assert a11y_data["metrics"]["total_criteria_checked"] >= 5
    assert a11y_data["metrics"]["wcag_score"] > 0
    assert len(a11y_data["defects"]) >= 5
    assert len(a11y_data["landmarks"]) >= 3
