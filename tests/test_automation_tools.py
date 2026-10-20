"""
Unit and integration tests for CHARLO Popular Tools QA & Test Automation Engine.

Tests:
- Web: Playwright & Selenium WebDriver 4
- Windows: WinAppDriver (UIAutomation3) & Ranorex Desktop
- Android: Appium Mobile & Espresso Native Android
- Copiable Corporate Client Deliverable Generator (Markdown & Plaintext)
- Standalone QA HTML Deliverable Report
"""

import pytest
from charlo.core.models import TargetType, ScanTarget, CheckFinding, CheckStatus, Severity, ScanLevel
from charlo.core.engine import ScanEngine
from charlo.analyzers.automation_tools import (
    PopularToolsAutomationTester, AutomationReport, AutomationTestSuite, AutomationTestCase
)
from charlo.reporting.html_reporter import HTMLReporter


def test_web_automation_playwright_and_selenium():
    """Verify Web application testing produces Playwright & Selenium suites."""
    target = ScanTarget(target_type=TargetType.WEB, target_path="https://pmec.ac.in", display_name="pmec.ac.in")
    
    findings = [
        CheckFinding(
            check_id="WEB-001",
            check_name="XSS Check",
            target_type=TargetType.WEB,
            category="Injection",
            severity=Severity.HIGH,
            status=CheckStatus.FAILED,
            title="Cross-Site Scripting (Reflected)",
            description="XSS in query parameter",
            affected_component="Search bar",
            evidence="alert(1) reflected",
            impact="Session hijacking",
            remediation="Sanitize input",
        )
    ]
    context = {
        "html_content": """
        <html>
            <head><title>PMEC Campus Portal</title></head>
            <body>
                <form action="/login" method="post">
                    <input type="text" name="username" id="user" required />
                    <input type="password" name="password" id="pass" />
                    <button type="submit">Log In</button>
                </form>
                <img src="/logo.png" alt="PMEC Logo" />
                <button style="width:50px;height:50px;">Apply Now</button>
            </body>
        </html>
        """,
        "status_code": 200,
        "response_time_ms": 120,
    }

    report = PopularToolsAutomationTester.run_tests(target, context, findings)

    assert isinstance(report, AutomationReport)
    assert "Web" in report.platform
    assert report.primary_tool == "Playwright"
    assert "Selenium" in report.secondary_tool
    assert report.total_tests >= 8
    assert report.passed_tests > 0
    assert report.quality_score > 0

    # Verify tools represented in test cases
    tools = [tc.tool for s in report.suites for tc in s.test_cases]
    assert any("Playwright" in t for t in tools)
    assert any("Selenium" in t for t in tools)

    # Verify Ready-to-run scripts
    assert "playwright" in report.ready_to_run_script_primary.lower()
    assert "selenium" in report.ready_to_run_script_secondary.lower()

    # Verify CI/CD pipeline
    assert "playwright" in report.ci_cd_pipeline_yaml.lower()

    # Verify copiable corporate client markdown
    md = report.copiable_client_markdown
    assert "PROFESSIONAL AUTOMATION QA TEST REPORT" in md
    assert "1. EXECUTIVE QA SUMMARY" in md
    assert "2. DETAILED TEST SUITE BREAKDOWN" in md
    assert "3. ACTIONABLE DEFECTS & REMEDIATION PATCHES" in md
    assert "4. AUTOMATION PIPELINE (CI/CD INTEGRATION)" in md
    assert "5. SIGN-OFF & CERTIFICATION" in md


def test_windows_automation_winappdriver_and_ranorex():
    """Verify Windows desktop (.exe / .msi) testing produces WinAppDriver & Ranorex suites."""
    target = ScanTarget(target_type=TargetType.EXE, target_path="C:\\Program Files\\App\\app.exe", display_name="app.exe")
    
    findings = [
        CheckFinding(
            check_id="EXE-001",
            check_name="DPI Awareness",
            target_type=TargetType.EXE,
            category="Manifest",
            severity=Severity.MEDIUM,
            status=CheckStatus.FAILED,
            title="Missing High-DPI Awareness Manifest",
            description="Application lacks Per-Monitor V2 DPI declaration.",
            affected_component="Manifest",
            evidence="No dpiAware tag",
            impact="Blurry rendering on high-res displays",
            remediation="Add dpiAwareness manifest element.",
        )
    ]
    context = {
        "file_size": 204800,
        "imports": {"USER32.dll": ["CreateWindowExW", "SetFocus"], "KERNEL32.dll": ["ExitProcess"]},
        "exports": [],
        "manifest": "",
    }

    report = PopularToolsAutomationTester.run_tests(target, context, findings)

    assert isinstance(report, AutomationReport)
    assert "Windows" in report.platform
    assert report.primary_tool == "WinAppDriver"
    assert "Ranorex" in report.secondary_tool
    assert report.total_tests >= 7
    assert report.passed_tests > 0

    # Verify WinAppDriver & Ranorex test cases
    tools = [tc.tool for s in report.suites for tc in s.test_cases]
    assert any("WinAppDriver" in t for t in tools)
    assert any("Ranorex" in t for t in tools)

    # Verify Ready-to-run scripts
    assert "WindowsDriver" in report.ready_to_run_script_primary
    assert "Ranorex" in report.ready_to_run_script_secondary

    # Verify CI/CD pipeline for Windows
    assert "windows-latest" in report.ci_cd_pipeline_yaml
    assert "WinAppDriver.exe" in report.ci_cd_pipeline_yaml

    # Verify copiable deliverable
    assert "WinAppDriver" in report.copiable_client_markdown
    assert "Ranorex" in report.copiable_client_markdown


def test_android_automation_appium_and_espresso():
    """Verify Android mobile (.apk) testing produces Appium & Espresso suites."""
    target = ScanTarget(target_type=TargetType.APK, target_path="C:\\Builds\\mobile-release.apk", display_name="mobile-release.apk")
    
    findings = [
        CheckFinding(
            check_id="APK-001",
            check_name="Exported Activity",
            target_type=TargetType.APK,
            category="Manifest",
            severity=Severity.HIGH,
            status=CheckStatus.FAILED,
            title="Exported Activity Without Permissions",
            description="Exported activity exposed without permission guard.",
            affected_component="AndroidManifest.xml",
            evidence="android:exported=true",
            impact="Unauthorized activity launching",
            remediation="Set exported=false.",
        )
    ]
    context = {
        "package_name": "com.company.mobileapp",
        "min_sdk": 24,
        "target_sdk": 34,
        "permissions": ["android.permission.INTERNET", "android.permission.CAMERA"],
    }

    report = PopularToolsAutomationTester.run_tests(target, context, findings)

    assert isinstance(report, AutomationReport)
    assert "Android" in report.platform
    assert "Appium" in report.primary_tool
    assert "Espresso" in report.secondary_tool
    assert report.total_tests >= 7
    assert report.passed_tests > 0

    # Verify Appium & Espresso test cases
    tools = [tc.tool for s in report.suites for tc in s.test_cases]
    assert any("Appium" in t for t in tools)
    assert any("Espresso" in t for t in tools)

    # Verify Ready-to-run scripts
    assert "UiAutomator2Options" in report.ready_to_run_script_primary
    assert "@RunWith(AndroidJUnit4::class)" in report.ready_to_run_script_secondary

    # Verify CI/CD pipeline
    assert "Appium" in report.ci_cd_pipeline_yaml
    assert "android-emulator-runner" in report.ci_cd_pipeline_yaml


def test_html_reporter_standalone_qa_deliverable():
    """Verify HTMLReporter generates a standalone client QA deliverable."""
    target = ScanTarget(target_type=TargetType.WEB, target_path="https://pmec.ac.in", display_name="pmec.ac.in")
    report = PopularToolsAutomationTester.run_tests(target, {}, [])

    html_out = HTMLReporter.generate_qa_report(report)
    assert "<!DOCTYPE html>" in html_out
    assert "QA AUTOMATION DELIVERABLE" in html_out
    assert report.primary_tool in html_out
    assert report.secondary_tool in html_out
    assert "Automated Test Cases Execution Grid" in html_out
    assert "Ready-to-Run Primary Automation Test Script" in html_out
    assert "CI/CD Pipeline Automation" in html_out
    assert "Copiable Plaintext / Markdown Client Deliverable" in html_out


def test_scan_engine_e2e_automation_integration():
    """Verify ScanEngine runs popular tools QA tester and saves report in metadata."""
    res = ScanEngine.run_scan("https://pmec.ac.in", TargetType.WEB, ScanLevel.BASIC)
    assert res.target is not None
    assert "automation_report" in res.target.metadata
    auto_report = res.target.metadata["automation_report"]
    assert "Web" in auto_report["platform"]
    assert auto_report["primary_tool"] == "Playwright"
    assert "Selenium" in auto_report["secondary_tool"]
    assert auto_report["total_tests"] >= 8
    assert len(auto_report["copiable_client_markdown"]) > 500
