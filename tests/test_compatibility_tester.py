"""
Unit tests for CHARLO Cross-Platform Compatibility, Multi-Device Viewport & WCAG Accessibility Testing Engine.
"""

import pytest
from charlo.core.models import ScanTarget, TargetType, CheckFinding, CheckStatus, Severity, ScanLevel
from charlo.analyzers.compatibility_tester import (
    CompatibilityTester,
    ViewportDevice,
    A11yDefect,
    CompatibilityReport,
)
from charlo.reporting.html_reporter import HTMLReporter
from charlo.core.engine import ScanEngine


def test_compatibility_tester_run_tests_basic():
    """Verify CompatibilityTester creates comprehensive multi-device viewport & A11y report."""
    target = ScanTarget(
        target_path="https://pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC Portal",
    )

    report = CompatibilityTester.run_tests(target)
    assert isinstance(report, CompatibilityReport)
    assert report.target_name == "PMEC Portal"
    assert report.target_type == "web"
    assert len(report.devices) == 6
    assert len(report.defects) >= 5
    assert report.total_viewports_tested == len(report.devices)
    assert report.total_checks >= 5
    assert 0.0 <= report.compatibility_score <= 100.0
    assert report.overall_status in [
        "WCAG AA CERTIFIED",
        "ADVISORY WARNINGS IDENTIFIED",
        "DEFECTS REQUIRING ATTENTION",
        "RESPONSIVE INTEGRITY FAILURE",
    ]


def test_compatibility_tester_devices_matrix():
    """Verify standard device simulation matrix covers mobile, tablet, desktop, and 4k viewports."""
    target = ScanTarget(
        target_path="https://example.com",
        target_type=TargetType.WEB,
        display_name="Example",
    )

    report = CompatibilityTester.run_tests(target)
    dev_names = [d.name for d in report.devices]
    assert any("iPhone SE" in name for name in dev_names)
    assert any("iPhone 15" in name for name in dev_names)
    assert any("iPad Air" in name for name in dev_names)
    assert any("Desktop" in name for name in dev_names)
    assert any("4K" in name for name in dev_names)

    for dev in report.devices:
        assert dev.viewport_width > 0
        assert dev.viewport_height > 0
        assert dev.device_scale_factor >= 1.0
        assert dev.status in ["PASSED", "DEFECT", "WARNING"]
        assert len(dev.render_notes) > 0


def test_compatibility_tester_defects_and_wcag():
    """Verify A11yDefect items contain valid categories, WCAG criteria, and CSS remediation patches."""
    target = ScanTarget(
        target_path="https://enterprise.acme.corp",
        target_type=TargetType.WEB,
        display_name="Acme Enterprise",
    )

    report = CompatibilityTester.run_tests(target)
    categories = {d.category for d in report.defects}
    assert "Responsive Layout" in categories
    assert "Touch Ergonomics" in categories
    assert "WCAG Contrast" in categories
    assert "Form Accessibility" in categories
    assert "Viewport Config" in categories

    for defect in report.defects:
        assert defect.defect_id.startswith("A11Y-")
        assert defect.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert defect.status in ["PASSED", "DEFECT", "WARNING"]
        assert "WCAG" in defect.wcag_criterion
        assert len(defect.title) > 0
        assert len(defect.description) > 0
        assert len(defect.impact) > 0
        assert len(defect.remediation_code) > 0


def test_compatibility_tester_automation_scripts():
    """Verify generation of executable Playwright and Cypress matrix test suites."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = CompatibilityTester.run_tests(target)
    pw = report.playwright_matrix_script
    cy = report.cypress_matrix_script

    # Playwright assertions
    assert "sync_playwright" in pw
    assert "VIEWPORT_MATRIX" in pw
    assert "test_viewport_rendering_and_layout_cohesion" in pw
    assert "scroll_width <= client_width" in pw
    assert "screenshot" in pw

    # Cypress assertions
    assert "describe('Cross-Platform Compatibility" in cy
    assert "cy.viewport(" in cy
    assert "scrollWidth" in cy


def test_compatibility_tester_copiable_markdown():
    """Verify copiable corporate client deliverable markdown contains executive summary and tables."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = CompatibilityTester.run_tests(target)
    md = report.copiable_client_markdown

    assert "PROFESSIONAL COMPATIBILITY & A11Y AUDIT" in md
    assert "Target System:       Demo Corp" in md
    assert "Compatibility Score:" in md
    assert "MULTI-DEVICE VIEWPORT MATRIX EVALUATION" in md
    assert "DETAILED DEFECT MATRIX & REMEDIATION PATCHES" in md
    assert "AUTOMATION TEST SUITES GENERATED" in md


def test_compatibility_tester_dict_serialization():
    """Verify to_dict produces JSON-serializable structured dictionary."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = CompatibilityTester.run_tests(target)
    d = report.to_dict()

    assert d["target_name"] == "Demo Corp"
    assert isinstance(d["devices"], list)
    assert isinstance(d["defects"], list)
    assert len(d["devices"]) == 6
    assert "viewport_width" in d["devices"][0]
    assert "wcag_criterion" in d["defects"][0]


def test_compatibility_html_reporter():
    """Verify HTMLReporter generates standalone, publication-grade Compatibility & WCAG report."""
    target = ScanTarget(
        target_path="https://portal.bank.corp",
        target_type=TargetType.WEB,
        display_name="Secure Banking Core",
    )

    report = CompatibilityTester.run_tests(target)
    html = HTMLReporter.generate_compatibility_report(report)

    assert "<!DOCTYPE html>" in html
    assert "Secure Banking Core" in html
    assert "Responsive Viewport & WCAG Accessibility Deliverable" in html or "Responsive Viewport &amp; WCAG Accessibility Deliverable" in html
    assert "Multi-Device Viewport Simulation Matrix" in html
    assert "Playwright Multi-Device Matrix Test Script" in html
    assert "Cypress Multi-Device Viewport Test Script" in html


def test_compatibility_engine_scan_integration():
    """Verify ScanEngine executes CompatibilityTester and stores report in target metadata."""
    engine = ScanEngine()
    result = engine.run_scan(
        target_input="https://pmec.ac.in",
        target_type=TargetType.WEB,
        level=ScanLevel.BASIC
    )

    assert "compatibility_report" in result.target.metadata
    compat_meta = result.target.metadata["compatibility_report"]
    assert "PMEC" in compat_meta["target_name"] or "pmec" in compat_meta["target_name"]
    assert compat_meta["total_viewports_tested"] == 6
    assert len(compat_meta["defects"]) >= 5
