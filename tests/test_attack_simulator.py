"""
Tests for CHARLO Testing Agent - Theoretical Attack Resilience & Survival Simulator.
Verifies survival calculations for Web, Windows EXE, and Mobile attack vectors.
"""

import pytest
from charlo.core.models import (
    TargetType,
    ScanLevel,
    CheckStatus,
    Severity,
    CheckFinding,
    ScanTarget,
    ScanResult,
)
from charlo.core.engine import ScanEngine
from charlo.analyzers.attack_simulator import (
    AttackResilienceSimulator,
    AttackSimulationReport,
    AttackScenarioResult,
)


def _make_finding(check_id: str, status: CheckStatus, severity: Severity = Severity.HIGH) -> CheckFinding:
    return CheckFinding(
        check_id=check_id,
        check_name=f"Mock Check {check_id}",
        target_type=TargetType.WEB,
        category="Security",
        status=status,
        severity=severity,
        title=f"Finding for {check_id}",
        description="Simulated test description",
        affected_component="Target Module",
        evidence="Simulated test evidence",
        impact="Simulated impact",
        remediation="Simulated fix",
    )


def test_web_attack_resilience_hardened():
    """Verify that a target with active defenses achieves high survival scores."""
    findings = [
        _make_finding("WEB-001", CheckStatus.PASSED, Severity.INFO),
        _make_finding("WEB-003", CheckStatus.PASSED, Severity.INFO),  # Strict CSP
        _make_finding("WEB-007", CheckStatus.PASSED, Severity.INFO),  # HttpOnly cookies
        _make_finding("WEB-028", CheckStatus.PASSED, Severity.INFO),  # Rate limiting active
        _make_finding("BUG-WEB-002", CheckStatus.PASSED, Severity.INFO),
        _make_finding("BUG-WEB-003", CheckStatus.PASSED, Severity.INFO),
    ]
    context = {"headers": {"server": "cloudflare", "cf-ray": "12345"}}

    report = AttackResilienceSimulator.simulate_target(
        target_name="https://hardened-portal.com",
        target_type=TargetType.WEB,
        findings=findings,
        context=context,
    )

    assert isinstance(report, AttackSimulationReport)
    assert report.total_attacks_tested >= 6
    assert report.overall_survival_chance >= 75.0
    assert report.hardened_count >= 4

    # Check SQLi
    sqli = next((a for a in report.attacks if a.attack_id == "ATK-WEB-SQLI"), None)
    assert sqli is not None
    assert sqli.survival_chance >= 75.0
    assert "Zero server-side database stack trace or debug pages leaking" in sqli.mitigating_controls_active

    # Check DDoS
    ddos = next((a for a in report.attacks if a.attack_id == "ATK-WEB-DDOS"), None)
    assert ddos is not None
    assert ddos.survival_chance >= 70.0

    # Check XSS
    xss = next((a for a in report.attacks if a.attack_id == "ATK-WEB-XSS"), None)
    assert xss is not None
    assert xss.survival_chance >= 80.0


def test_web_attack_resilience_vulnerable():
    """Verify that missing defenses and critical exposures drastically penalize survival rate."""
    findings = [
        _make_finding("WEB-003", CheckStatus.FAILED, Severity.HIGH),    # Missing CSP
        _make_finding("WEB-007", CheckStatus.FAILED, Severity.MEDIUM),  # Missing HttpOnly
        _make_finding("WEB-018", CheckStatus.FAILED, Severity.CRITICAL),# Leaked .env
        _make_finding("WEB-028", CheckStatus.FAILED, Severity.LOW),     # Missing Rate Limiting
        _make_finding("BUG-WEB-003", CheckStatus.FAILED, Severity.HIGH),# Stack Trace Leak
    ]

    report = AttackResilienceSimulator.simulate_target(
        target_name="https://vulnerable-site.org",
        target_type=TargetType.WEB,
        findings=findings,
        context={},
    )

    assert report.overall_survival_chance < 50.0
    assert report.critical_exposure_count >= 1

    # Check SQLi penalty from leaked .env and stack trace
    sqli = next((a for a in report.attacks if a.attack_id == "ATK-WEB-SQLI"), None)
    assert sqli is not None
    assert sqli.survival_chance < 40.0
    penalties = [v.check_id for v in sqli.contributing_vulnerabilities]
    assert "BUG-WEB-003" in penalties or "WEB-018" in penalties

    # Check XSS penalty from missing CSP and HttpOnly
    xss = next((a for a in report.attacks if a.attack_id == "ATK-WEB-XSS"), None)
    assert xss is not None
    assert xss.survival_chance < 40.0


def test_exe_buffer_overflow_and_dll_resilience():
    """Verify Windows binary attack resilience against Buffer Overflow and DLL Side-Loading."""
    findings = [
        _make_finding("EXE-001", CheckStatus.FAILED, Severity.HIGH),  # Missing ASLR
        _make_finding("EXE-002", CheckStatus.FAILED, Severity.HIGH),  # Missing DEP
        _make_finding("EXE-003", CheckStatus.FAILED, Severity.MEDIUM),# Unsigned binary
        _make_finding("EXE-014", CheckStatus.FAILED, Severity.HIGH),  # Missing /GS
    ]

    report = AttackResilienceSimulator.simulate_target(
        target_name="legacy_app.exe",
        target_type=TargetType.EXE,
        findings=findings,
        context={"machine_arch": "AMD64 (64-bit)"},
    )

    bof = next((a for a in report.attacks if a.attack_id == "ATK-EXE-BOF"), None)
    assert bof is not None
    # Missing ASLR, DEP, and GS canary heavily reduces survival
    assert bof.survival_chance < 30.0
    assert "Critical Exposure" in bof.verdict or "Low Resilience" in bof.verdict

    dll = next((a for a in report.attacks if a.attack_id == "ATK-EXE-DLL"), None)
    assert dll is not None
    assert dll.survival_chance < 50.0


def test_windows_active_directory_identity_attacks():
    """Verify Pass-the-Hash and Kerberoasting threat simulation."""
    findings_vuln = [
        _make_finding("EXE-010", CheckStatus.FAILED, Severity.HIGH),  # Leaked domain credentials
        _make_finding("EXE-013", CheckStatus.FAILED, Severity.HIGH),  # uiAccess=true
    ]

    report = AttackResilienceSimulator.simulate_target(
        target_name="domain_tool.exe",
        target_type=TargetType.EXE,
        findings=findings_vuln,
        context={"machine_arch": "AMD64 (64-bit)"},
    )

    pth = next((a for a in report.attacks if a.attack_id == "ATK-WIN-AD-PTH"), None)
    assert pth is not None
    assert pth.survival_chance < 45.0
    assert any("Hardcoded Credentials" in v.title for v in pth.contributing_vulnerabilities)


def test_infrastructure_ransomware_and_ssrf():
    """Verify cross-platform Ransomware and SSRF resilience evaluation."""
    findings = [
        _make_finding("WEB-016", CheckStatus.FAILED, Severity.HIGH),   # Open Redirection
        _make_finding("BUG-WEB-002", CheckStatus.FAILED, Severity.LOW),# Unvalidated URL input
        _make_finding("WEB-017", CheckStatus.FAILED, Severity.CRITICAL), # .git leaked
    ]

    report = AttackResilienceSimulator.simulate_target(
        target_name="https://enterprise-cloud.com",
        target_type=TargetType.WEB,
        findings=findings,
    )

    ssrf = next((a for a in report.attacks if a.attack_id == "ATK-INF-SSRF"), None)
    assert ssrf is not None
    assert ssrf.survival_chance < 50.0

    rce = next((a for a in report.attacks if a.attack_id == "ATK-INF-RANSOM"), None)
    assert rce is not None
    assert rce.survival_chance < 45.0


def test_apk_mobile_attack_resilience():
    """Verify Android mobile threat simulation."""
    findings = [
        _make_finding("APK-001", CheckStatus.FAILED, Severity.CRITICAL),  # debuggable=true
        _make_finding("APK-004", CheckStatus.FAILED, Severity.HIGH),      # exported components
    ]

    report = AttackResilienceSimulator.simulate_target(
        target_name="banking_app.apk",
        target_type=TargetType.APK,
        findings=findings,
    )

    apk_atk = next((a for a in report.attacks if a.attack_id == "ATK-APK-HIJACK"), None)
    assert apk_atk is not None
    assert apk_atk.survival_chance < 30.0


def test_full_engine_attack_simulation():
    """Verify ScanEngine.run_attack_simulation end-to-end."""
    report = ScanEngine.run_attack_simulation(
        target_input="https://example.com",
        target_type=TargetType.WEB,
        level=ScanLevel.BASIC,
    )

    assert isinstance(report, AttackSimulationReport)
    assert report.total_attacks_tested >= 5
    assert 5.0 <= report.overall_survival_chance <= 98.0
    assert len(report.attacks) >= 5
