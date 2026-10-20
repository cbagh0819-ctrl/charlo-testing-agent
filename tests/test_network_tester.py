"""
Unit tests for CHARLO Network Protocol, TLS/SSL Cryptographic Cipher & Certificate Testing Engine.
"""

import pytest
from charlo.core.models import ScanTarget, TargetType, CheckFinding, CheckStatus, Severity, ScanLevel
from charlo.analyzers.network_tester import (
    NetworkTester,
    TlsCipherInspection,
    CertificateInspection,
    DnsSecMailSecurity,
    NetworkDefect,
    NetworkTestReport,
)
from charlo.reporting.html_reporter import HTMLReporter
from charlo.core.engine import ScanEngine


def test_network_tester_run_tests_basic():
    """Verify NetworkTester creates comprehensive TLS protocol, cipher, and certificate reports."""
    target = ScanTarget(
        target_path="https://pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC Enterprise Gateway",
    )

    report = NetworkTester.run_tests(target)
    assert isinstance(report, NetworkTestReport)
    assert report.target_name == "PMEC Enterprise Gateway"
    assert report.target_host == "pmec.ac.in"
    assert report.port == 443
    assert report.tls_grade in ["A+", "A", "B", "C", "F"]
    assert 0.0 <= report.crypto_score <= 100.0
    assert report.total_checks >= 5
    assert len(report.defects) >= 5
    assert report.cipher_info is not None
    assert report.cert_info is not None
    assert report.dns_mail_info is not None
    assert report.overall_status in [
        "ENTERPRISE HARDENED",
        "DEFECTS REQUIRING ATTENTION",
        "CRYPTOGRAPHIC FAILURE",
    ]


def test_network_tester_ciphers_and_pfs():
    """Verify TlsCipherInspection captures PFS, AEAD, and TLS 1.3 protocol attributes."""
    target = ScanTarget(
        target_path="https://api.pmec.ac.in:8443",
        target_type=TargetType.WEB,
        display_name="API Gateway",
    )

    report = NetworkTester.run_tests(target)
    ci = report.cipher_info
    assert ci is not None
    assert "TLSv1.3" in ci.protocol_version or "TLSv1.2" in ci.protocol_version
    assert ci.perfect_forward_secrecy is True
    assert ci.tls_compression_disabled is True
    assert len(ci.cipher_suite) > 0
    assert len(ci.key_exchange) > 0


def test_network_tester_cert_health():
    """Verify CertificateInspection captures expiration days, key size, and OCSP status."""
    target = ScanTarget(
        target_path="https://pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC Test",
    )

    report = NetworkTester.run_tests(target)
    cert = report.cert_info
    assert cert is not None
    assert cert.common_name == "pmec.ac.in"
    assert cert.days_to_expiration > 0
    assert "RSA" in cert.key_type_and_bits or "ECDSA" in cert.key_type_and_bits
    assert len(cert.issuer_org) > 0


def test_network_tester_dns_and_dmarc():
    """Verify DnsSecMailSecurity captures ALPN h2 support and anti-spoofing policies."""
    target = ScanTarget(
        target_path="https://pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC Test",
    )

    report = NetworkTester.run_tests(target)
    dns = report.dns_mail_info
    assert dns is not None
    assert dns.alpn_http2_supported is True
    assert len(dns.dmarc_policy) > 0


def test_network_tester_defects_and_remediations():
    """Verify NetworkDefect items contain valid categories, severities, and server configs."""
    target = ScanTarget(
        target_path="https://enterprise.acme.corp",
        target_type=TargetType.WEB,
        display_name="Acme Enterprise",
    )

    report = NetworkTester.run_tests(target)
    categories = {d.category for d in report.defects}
    assert "TLS Protocol" in categories
    assert "Cipher Suites" in categories
    assert "Certificate Health" in categories
    assert "DNS & Spoofing" in categories
    assert "Transport Defense" in categories

    for defect in report.defects:
        assert defect.defect_id.startswith("NET-")
        assert defect.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        assert defect.status in ["PASSED", "DEFECT", "WARNING"]
        assert len(defect.title) > 0
        assert len(defect.description) > 0
        assert len(defect.impact) > 0
        assert len(defect.remediation_config) > 0


def test_network_tester_openssl_script():
    """Verify generation of executable OpenSSL diagnostic shell script."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = NetworkTester.run_tests(target)
    script = report.openssl_diagnostic_script

    assert "#!/usr/bin/env bash" in script
    assert "openssl s_client -connect" in script
    assert "-tls1_3" in script
    assert "-tls1" in script
    assert "OCSP Response Status" in script
    assert "dig +short CAA" in script


def test_network_tester_copiable_markdown():
    """Verify copiable corporate client deliverable markdown contains executive summary and telemetry."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = NetworkTester.run_tests(target)
    md = report.copiable_client_markdown

    assert "PROFESSIONAL TLS & NETWORK AUDIT DELIVERABLE" in md
    assert "Target System:       Demo Corp" in md
    assert "TLS Health Grade:" in md
    assert "CRYPTOGRAPHIC & CERTIFICATE TELEMETRY" in md
    assert "DETAILED DEFECT MATRIX & REMEDIATION CONFIGURATIONS" in md
    assert "AUTOMATION & DIAGNOSTIC ARTIFACTS AVAILABLE" in md


def test_network_tester_dict_serialization():
    """Verify to_dict produces JSON-serializable structured dictionary."""
    target = ScanTarget(
        target_path="https://demo.corp",
        target_type=TargetType.WEB,
        display_name="Demo Corp",
    )

    report = NetworkTester.run_tests(target)
    d = report.to_dict()

    assert d["target_name"] == "Demo Corp"
    assert "cipher_info" in d
    assert "cert_info" in d
    assert "dns_mail_info" in d
    assert isinstance(d["defects"], list)
    assert len(d["defects"]) >= 5
    assert d["cipher_info"]["perfect_forward_secrecy"] is True


def test_network_html_reporter():
    """Verify HTMLReporter generates standalone, publication-grade Network & TLS report."""
    target = ScanTarget(
        target_path="https://portal.bank.corp",
        target_type=TargetType.WEB,
        display_name="Secure Banking Core",
    )

    report = NetworkTester.run_tests(target)
    html = HTMLReporter.generate_network_report(report)

    assert "<!DOCTYPE html>" in html
    assert "Secure Banking Core" in html
    assert "Network Protocol & Cryptographic TLS Deliverable" in html or "Network Protocol &amp; Cryptographic TLS Deliverable" in html
    assert "TLS Handshake & Cipher Suite Negotiation" in html or "TLS Handshake &amp; Cipher Suite Negotiation" in html
    assert "X.509 Certificate Chain of Trust & Expiration" in html or "X.509 Certificate Chain of Trust &amp; Expiration" in html
    assert "Automated OpenSSL Diagnostic Script" in html


def test_network_engine_scan_integration():
    """Verify ScanEngine executes NetworkTester and stores report in target metadata."""
    engine = ScanEngine()
    result = engine.run_scan(
        target_input="https://pmec.ac.in",
        target_type=TargetType.WEB,
        level=ScanLevel.BASIC
    )

    assert "network_report" in result.target.metadata
    net_meta = result.target.metadata["network_report"]
    assert "PMEC" in net_meta["target_name"] or "pmec" in net_meta["target_name"]
    assert net_meta["tls_grade"] in ["A+", "A", "B", "C", "F"]
    assert len(net_meta["defects"]) >= 5
