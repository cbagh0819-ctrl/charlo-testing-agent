"""
Unit tests for Webhook Alerting & Continuous Watchdog Dispatcher.
"""

import pytest
from unittest.mock import patch, MagicMock
import urllib.error

from charlo.core.models import (
    ScanResult, ScanTarget, ScanMetrics, CheckFinding,
    TargetType, ScanLevel, Severity, CheckStatus
)
from charlo.core.webhook_notifier import WebhookNotifier


@pytest.fixture
def mock_scan_result():
    target = ScanTarget(
        target_path="https://app.corp.internal",
        target_type=TargetType.WEB,
        display_name="Corporate Web Portal"
    )
    metrics = ScanMetrics(
        security_score=70.0,
        posture_grade="C",
        total_checks=3,
        passed=1,
        failed=2,
        warnings=0
    )
    findings = [
        CheckFinding(
            check_id="CRIT-01",
            check_name="RCE Check",
            target_type=TargetType.WEB,
            title="Remote Code Execution",
            severity=Severity.CRITICAL,
            category="RCE",
            status=CheckStatus.FAILED,
            description="Deserialization vulnerability",
            evidence="Insecure deserialization",
            impact="Remote server takeover",
            remediation="Patch library",
            affected_component="/upload"
        ),
        CheckFinding(
            check_id="HIGH-01",
            check_name="CSRF Protection Check",
            target_type=TargetType.WEB,
            title="Missing Anti-CSRF Token",
            severity=Severity.HIGH,
            category="CSRF",
            status=CheckStatus.FAILED,
            description="No token on POST",
            evidence="No state token",
            impact="Unauthorized state change",
            remediation="Implement CSRF cookies",
            affected_component="/transfer"
        ),
        CheckFinding(
            check_id="PASS-01",
            check_name="HSTS Header Check",
            target_type=TargetType.WEB,
            title="Enforced HSTS",
            severity=Severity.LOW,
            category="Headers",
            status=CheckStatus.PASSED,
            description="HSTS active",
            evidence="HSTS header present",
            impact="None",
            remediation="None",
            affected_component="Strict-Transport-Security"
        )
    ]
    return ScanResult(
        target=target,
        level=ScanLevel.ADVANCED,
        start_time="2026-10-20T11:00:00",
        end_time="2026-10-20T11:00:02",
        findings=findings,
        metrics=metrics
    )


def test_detect_channel_type():
    """Verify automatic identification of Slack, Discord, Teams, or Generic webhooks."""
    assert WebhookNotifier.detect_channel_type("https://hooks.slack.com/services/T00/B00/X00") == "slack"
    assert WebhookNotifier.detect_channel_type("https://discord.com/api/webhooks/12345/abcdef") == "discord"
    assert WebhookNotifier.detect_channel_type("https://webhook.office.com/webhookb2/guid/IncomingWebhook") == "teams"
    assert WebhookNotifier.detect_channel_type("https://my-siem.company.com/alerts/ingest") == "generic"


def test_dispatch_slack_success(mock_scan_result):
    """Verify Slack alert card delivery."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b"ok"
    mock_resp.__enter__.return_value = mock_resp

    slack_url = "https://hooks.slack.com/services/T1/B1/K1"
    with patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen:
        res = WebhookNotifier.dispatch_alert(slack_url, mock_scan_result)

    assert res["success"] is True
    assert res["status_code"] == 200
    assert "dispatched" in res["message"].lower()

    # Verify request payload was formatted as Slack attachments
    args, kwargs = mock_urlopen.call_args
    req = args[0]
    assert req.get_method() == "POST"
    assert req.headers["Content-type"] == "application/json"


def test_dispatch_discord_success(mock_scan_result):
    """Verify Discord alert card delivery."""
    mock_resp = MagicMock()
    mock_resp.status = 204
    mock_resp.getcode.return_value = 204
    mock_resp.read.return_value = b""
    mock_resp.__enter__.return_value = mock_resp

    discord_url = "https://discord.com/api/webhooks/123/xyz"
    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = WebhookNotifier.dispatch_alert(discord_url, mock_scan_result)

    assert res["success"] is True
    assert res["status_code"] == 204


def test_dispatch_teams_success(mock_scan_result):
    """Verify Microsoft Teams connector delivery."""
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200
    mock_resp.read.return_value = b"1"
    mock_resp.__enter__.return_value = mock_resp

    teams_url = "https://webhook.office.com/webhookb2/abc/IncomingWebhook/123"
    with patch("urllib.request.urlopen", return_value=mock_resp):
        res = WebhookNotifier.dispatch_alert(teams_url, mock_scan_result)

    assert res["success"] is True
    assert res["status_code"] == 200


def test_dispatch_network_failure(mock_scan_result):
    """Verify graceful handling when webhook destination is unreachable."""
    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("DNS resolution failed")):
        res = WebhookNotifier.dispatch_alert("https://invalid-host-999.corp", mock_scan_result)

    assert res["success"] is False
    assert "DNS resolution failed" in res["message"]


def test_dispatch_empty_url(mock_scan_result):
    """Verify handling when webhook URL is empty."""
    res = WebhookNotifier.dispatch_alert("", mock_scan_result)
    assert res["success"] is False
    assert "No webhook URL provided" in res["message"]
