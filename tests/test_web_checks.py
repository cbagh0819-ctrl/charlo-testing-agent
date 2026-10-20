"""
Tests for Website Analyzer and Security Checks.
"""

from charlo.core.models import TargetType, ScanTarget, CheckStatus
from charlo.checks.web_checks import (
    WebCheckHTTPS, WebCheckHSTS, WebCheckCSP, WebCheckXFrameOptions
)


def test_mock_web_context():
    target = ScanTarget(
        target_type=TargetType.WEB,
        target_path="https://example.com",
        display_name="example.com",
    )

    # Insecure context simulation
    insecure_context = {
        "valid_url": True,
        "is_https": False,
        "status_code": 200,
        "hsts_present": False,
        "csp_present": False,
        "x_frame_options": None,
    }

    # Test HTTPS
    https_check = WebCheckHTTPS()
    f_https = https_check.run(target, insecure_context)
    assert f_https.check_id == "WEB-001"
    assert f_https.status == CheckStatus.FAILED

    # Test HSTS
    hsts_check = WebCheckHSTS()
    f_hsts = hsts_check.run(target, insecure_context)
    assert f_hsts.check_id == "WEB-002"
    assert f_hsts.status == CheckStatus.FAILED

    # Test CSP
    csp_check = WebCheckCSP()
    f_csp = csp_check.run(target, insecure_context)
    assert f_csp.check_id == "WEB-003"
    assert f_csp.status == CheckStatus.FAILED

    # Secure context simulation
    secure_context = {
        "valid_url": True,
        "is_https": True,
        "normalized_url": "https://example.com",
        "status_code": 200,
        "hsts_present": True,
        "hsts_value": "max-age=31536000; includeSubDomains",
        "csp_present": True,
        "csp_value": "default-src 'self'",
        "x_frame_options": "DENY",
    }

    assert https_check.run(target, secure_context).status == CheckStatus.PASSED
    assert hsts_check.run(target, secure_context).status == CheckStatus.PASSED
    assert csp_check.run(target, secure_context).status == CheckStatus.PASSED
    assert WebCheckXFrameOptions().run(target, secure_context).status == CheckStatus.PASSED
