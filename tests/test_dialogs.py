"""
Unit tests for Specialized Enterprise Security Dialogs:
- PoCSandboxDialog
- AutoPatchDialog
- WebhookConfigDialog
"""

import os
import pytest
from unittest.mock import patch, MagicMock

os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication
from charlo.ui.dialogs import PoCSandboxDialog, AutoPatchDialog, WebhookConfigDialog
from charlo.core.models import (
    ScanResult, ScanTarget, ScanMetrics, CheckFinding,
    TargetType, ScanLevel, Severity, CheckStatus
)


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


@pytest.fixture
def mock_scan_result():
    target = ScanTarget(
        target_path="https://api.pmec.ac.in",
        target_type=TargetType.WEB,
        display_name="PMEC Test"
    )
    metrics = ScanMetrics(
        security_score=85.0,
        posture_grade="B",
        total_checks=2,
        passed=1,
        failed=1,
        warnings=0
    )
    finding = CheckFinding(
        check_id="SQLI-01",
        check_name="SQL Injection",
        target_type=TargetType.WEB,
        title="SQL Injection",
        severity=Severity.HIGH,
        category="Injection",
        status=CheckStatus.FAILED,
        description="Query concatenation",
        evidence="syntax error in sql",
        impact="Database leak",
        remediation="Parameterize queries",
        affected_component="/api/users"
    )
    return ScanResult(
        target=target,
        level=ScanLevel.ADVANCED,
        start_time="2026-10-20T12:00:00",
        end_time="2026-10-20T12:00:01",
        findings=[finding],
        metrics=metrics
    )


def test_poc_sandbox_dialog_initialization(qapp):
    """Verify PoCSandboxDialog initializes with default telemetry and inputs."""
    dlg = PoCSandboxDialog(target_url="https://api.example.com", flaw_id="FLAW-001", default_method="POST")
    assert dlg.url_edit.text() == "https://api.example.com"
    assert dlg.flaw_edit.text() == "FLAW-001"
    assert dlg.method_combo.currentText() == "POST"
    assert dlg.card_status.val_lbl.text() == "--"
    assert dlg.card_verdict.val_lbl.text() == "Awaiting Execution"


def test_poc_sandbox_dialog_run(qapp):
    """Verify executing PoC inside dialog updates badges and response views."""
    dlg = PoCSandboxDialog(target_url="https://api.example.com", flaw_id="FLAW-001")

    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.getcode.return_value = 200
    mock_resp.headers = {"Server": "Nginx", "Content-Type": "application/json"}
    mock_resp.read.return_value = b'{"status": "ok", "probe": "safe"}'
    mock_resp.__enter__.return_value = mock_resp

    with patch("charlo.core.poc_runner.urllib.request.urlopen", return_value=mock_resp):
        dlg._run_poc()

    assert dlg.card_status.val_lbl.text() == "200"
    assert dlg.card_verdict.val_lbl.text() == "INCONCLUSIVE" or dlg.card_verdict.val_lbl.text() == "MITIGATED"
    assert "Server: Nginx" in dlg.headers_view.toPlainText()
    assert '{"status": "ok"' in dlg.body_view.toPlainText()


def test_autopatch_dialog_initialization(qapp):
    """Verify AutoPatchDialog generates unified diff upon opening."""
    sample = (
        'def fetch_user(uid):\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = \'{uid}\'")\n'
    )
    dlg = AutoPatchDialog(flaw_type="SQL_INJECTION", sample_code=sample, target_file="user_service.py")

    assert dlg.rule_combo.currentText() == "SQL_INJECTION"
    diff_text = dlg.diff_view.toPlainText()
    assert "--- a/user_service.py" in diff_text
    assert "+++ b/user_service.py" in diff_text
    assert "cursor.execute(" in diff_text


def test_autopatch_dialog_clipboard_copy(qapp):
    """Verify copying patch to system clipboard."""
    dlg = AutoPatchDialog(sample_code="a = 1\n")
    dlg._copy_patch()
    cb = QApplication.clipboard().text()
    assert "--- a/" in cb or "b/" in cb or len(cb) > 0
    assert "copied to clipboard" in dlg.status_lbl.text().lower()


def test_webhook_dialog_platform_detection(qapp, mock_scan_result):
    """Verify WebhookConfigDialog dynamic detection of platform."""
    dlg = WebhookConfigDialog(result=mock_scan_result)

    dlg.url_edit.setText("https://hooks.slack.com/services/1/2/3")
    assert "Slack" in dlg.channel_badge.text()

    dlg.url_edit.setText("https://discord.com/api/webhooks/1/2")
    assert "Discord" in dlg.channel_badge.text()

    dlg.url_edit.setText("https://webhook.office.com/webhookb2/guid/IncomingWebhook")
    assert "Microsoft Teams" in dlg.channel_badge.text()
