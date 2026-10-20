"""
CHARLO Testing Agent - Specialized Enterprise Security Dialogs.
Includes:
- PoCSandboxDialog: Live Interactive PoC Exploit & Sandbox Runner
- AutoPatchDialog: Autonomous Code Auto-Patcher & Unified Git Diff Engine
- WebhookConfigDialog: Instant Webhook Alert Dispatcher (Slack, Discord, MS Teams)
"""

import os
from typing import Optional, Dict, Any
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QLineEdit, QComboBox, QTextEdit, QFrame,
    QFileDialog, QMessageBox, QApplication, QSplitter
)

from ..core.models import ScanResult, CheckFinding
from ..core.poc_runner import PocRunner, PocExecutionResult
from ..core.auto_patcher import AutoPatcher, PatchResult
from ..core.webhook_notifier import WebhookNotifier


class PoCSandboxDialog(QDialog):
    """
    Live Interactive PoC Exploit & Sandbox Runner Dialog.
    Dispatches safe, non-destructive HTTP requests to live targets
    to verify vulnerability existence, measure latency, and capture response headers.
    """

    def __init__(
        self,
        parent=None,
        target_url: str = "",
        flaw_id: str = "LIVE-POC-PROBE",
        probe_type: str = "custom",
        default_method: str = "GET"
    ):
        super().__init__(parent)
        self.setWindowTitle("CHARLO Live PoC Exploit & Sandbox Runner")
        self.resize(780, 620)
        self.setStyleSheet("""
            QDialog {
                background-color: #0b0f19;
                color: #e4e9f2;
            }
            QLabel {
                color: #cbd5e1;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #12151d;
                border: 1px solid #1e2434;
                border-radius: 7px;
                padding: 6px 10px;
                color: #ffffff;
                font-size: 12.5px;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border-color: #ff2a44;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header Title
        title_box = QHBoxLayout()
        icon_lbl = QLabel("▶")
        icon_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #ff2a44;")
        title_lbl = QLabel("LIVE POC EXPLOIT & SANDBOX RUNNER")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #ffffff; letter-spacing: 0.5px;")
        sub_lbl = QLabel("Isolated HTTP Sandbox Probe")
        sub_lbl.setStyleSheet("font-size: 11px; color: #8b93a4; font-weight: 600;")
        title_box.addWidget(icon_lbl)
        title_box.addWidget(title_lbl)
        title_box.addStretch()
        title_box.addWidget(sub_lbl)
        layout.addLayout(title_box)

        # Configuration Form Card
        cfg_frame = QFrame()
        cfg_frame.setStyleSheet("background-color: #0f1422; border: 1px solid #1a2333; border-radius: 9px;")
        cfg_layout = QGridLayout(cfg_frame)
        cfg_layout.setContentsMargins(14, 12, 14, 12)
        cfg_layout.setSpacing(8)

        # Target URL
        cfg_layout.addWidget(QLabel("Target URL:"), 0, 0)
        self.url_edit = QLineEdit(target_url or "https://")
        self.url_edit.setPlaceholderText("https://example.com/api/v1/resource")
        cfg_layout.addWidget(self.url_edit, 0, 1, 1, 3)

        # Method & Probe Type & Flaw ID
        cfg_layout.addWidget(QLabel("HTTP Method:"), 1, 0)
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"])
        idx = self.method_combo.findText(default_method.upper())
        if idx >= 0:
            self.method_combo.setCurrentIndex(idx)
        cfg_layout.addWidget(self.method_combo, 1, 1)

        cfg_layout.addWidget(QLabel("Probe Signature:"), 1, 2)
        self.probe_combo = QComboBox()
        self.probe_combo.addItems([
            "custom (Standard Request)",
            "sql_error (Syntax Error Reflection)",
            "xss_probe (Unescaped Tag Reflection)",
            "traversal (Arbitrary Path Traversal)",
            "command_exec (Remote Execution Canary)",
            "info_disclosure (Environment/Config Leak)"
        ])
        for i in range(self.probe_combo.count()):
            if probe_type.lower() in self.probe_combo.itemText(i).lower():
                self.probe_combo.setCurrentIndex(i)
                break
        cfg_layout.addWidget(self.probe_combo, 1, 3)

        cfg_layout.addWidget(QLabel("Flaw Reference ID:"), 2, 0)
        self.flaw_edit = QLineEdit(flaw_id)
        cfg_layout.addWidget(self.flaw_edit, 2, 1)

        # Execute Button
        self.btn_run = QPushButton("⚡ Execute Live PoC Probe")
        self.btn_run.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff2a44, stop:1 #ff5268);
                color: #ffffff;
                font-weight: 800;
                font-size: 13px;
                border: none;
                border-radius: 7px;
                padding: 8px 18px;
            }
            QPushButton:hover {
                background: #ff475e;
            }
            QPushButton:pressed {
                background: #d61830;
            }
        """)
        self.btn_run.clicked.connect(self._run_poc)
        cfg_layout.addWidget(self.btn_run, 2, 2, 1, 2)

        layout.addWidget(cfg_frame)

        # Optional Custom Request Payload
        payload_label = QLabel("Optional Custom Request Body (POST / PUT JSON or form payload):")
        payload_label.setStyleSheet("font-size: 11px; color: #8b93a4;")
        layout.addWidget(payload_label)

        self.payload_edit = QTextEdit()
        self.payload_edit.setPlaceholderText('{\n  "query": "{ __schema { types { name } } }"\n}')
        self.payload_edit.setMaximumHeight(75)
        layout.addWidget(self.payload_edit)

        # Telemetry KPI Badges
        telemetry_box = QHBoxLayout()
        telemetry_box.setSpacing(10)

        self.card_status = self._create_badge("STATUS CODE", "--", "#8b93a4")
        self.card_latency = self._create_badge("LATENCY", "-- ms", "#00d4ff")
        self.card_verdict = self._create_badge("VERIFICATION VERDICT", "Awaiting Execution", "#8b93a4")

        telemetry_box.addWidget(self.card_status, 1)
        telemetry_box.addWidget(self.card_latency, 1)
        telemetry_box.addWidget(self.card_verdict, 2)
        layout.addLayout(telemetry_box)

        # Splitter: Response Headers on Left, Response Body on Right
        splitter = QSplitter(Qt.Horizontal)

        left_w = QFrame()
        left_layout = QVBoxLayout(left_w)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addWidget(QLabel("RESPONSE HEADERS:"))
        self.headers_view = QTextEdit()
        self.headers_view.setReadOnly(True)
        self.headers_view.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; background-color: #0b0f19;")
        left_layout.addWidget(self.headers_view)
        splitter.addWidget(left_w)

        right_w = QFrame()
        right_layout = QVBoxLayout(right_w)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(4)
        right_layout.addWidget(QLabel("RESPONSE BODY PREVIEW:"))
        self.body_view = QTextEdit()
        self.body_view.setReadOnly(True)
        self.body_view.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; background-color: #0b0f19;")
        right_layout.addWidget(self.body_view)
        splitter.addWidget(right_w)

        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)
        layout.addWidget(splitter, 1)

        # Close button
        btn_box = QHBoxLayout()
        self.summary_lbl = QLabel("")
        self.summary_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4;")
        self.summary_lbl.setWordWrap(True)
        btn_box.addWidget(self.summary_lbl, 1)

        self.btn_close = QPushButton("Close Sandbox")
        self.btn_close.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 7px; padding: 7px 18px; font-weight: 700;")
        self.btn_close.clicked.connect(self.accept)
        btn_box.addWidget(self.btn_close)
        layout.addLayout(btn_box)

    def _create_badge(self, title: str, val: str, color: str) -> QFrame:
        frame = QFrame()
        frame.setStyleSheet("background-color: #101420; border: 1px solid #1a2333; border-radius: 8px;")
        l = QVBoxLayout(frame)
        l.setContentsMargins(10, 8, 10, 8)
        l.setAlignment(Qt.AlignCenter)

        val_lbl = QLabel(val)
        val_lbl.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {color};")
        val_lbl.setAlignment(Qt.AlignCenter)

        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-size: 9.5px; font-weight: 700; color: #7b8497; text-transform: uppercase;")
        title_lbl.setAlignment(Qt.AlignCenter)

        l.addWidget(val_lbl)
        l.addWidget(title_lbl)
        frame.val_lbl = val_lbl
        frame.title_lbl = title_lbl
        return frame

    def _run_poc(self):
        target = self.url_edit.text().strip()
        if not target or target == "https://":
            QMessageBox.warning(self, "Invalid URL", "Please enter a valid target URL.")
            return

        method = self.method_combo.currentText()
        flaw_id = self.flaw_edit.text().strip() or "POC-PROBE"
        probe_text = self.probe_combo.currentText().split()[0].lower()
        body = self.payload_edit.toPlainText().strip() or None

        self.btn_run.setEnabled(False)
        self.btn_run.setText("⏳ Probing...")
        QApplication.processEvents()

        try:
            result = PocRunner.execute_poc(
                flaw_id=flaw_id,
                target_url=target,
                method=method,
                body=body,
                probe_type=probe_text if probe_text != "custom" else None
            )

            # Update telemetry
            code_str = str(result.status_code) if result.status_code else "ERR"
            code_color = "#00ff9d" if result.status_code and 200 <= result.status_code < 300 else "#ffb800" if result.status_code and 300 <= result.status_code < 500 else "#ff2a44"
            self.card_status.val_lbl.setText(code_str)
            self.card_status.val_lbl.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {code_color};")

            self.card_latency.val_lbl.setText(f"{result.latency_ms:.1f} ms")

            verdict_colors = {
                "CONFIRMED_VULNERABLE": "#ff2a44",
                "MITIGATED": "#00ff9d",
                "INCONCLUSIVE": "#ffb800",
                "ERROR": "#ff6b22"
            }
            v_color = verdict_colors.get(result.verification_status, "#8b93a4")
            self.card_verdict.val_lbl.setText(result.verification_status)
            self.card_verdict.val_lbl.setStyleSheet(f"font-size: 14px; font-weight: 800; color: {v_color};")

            # Headers view
            hdr_lines = [f"{k}: {v}" for k, v in result.response_headers.items()]
            self.headers_view.setText("\n".join(hdr_lines) if hdr_lines else "// No response headers returned")

            # Body view
            self.body_view.setText(result.response_body_preview or "// Empty response body")

            # Summary
            self.summary_lbl.setText(f"Probe Result: {result.analysis_summary}")

        except Exception as e:
            QMessageBox.critical(self, "Sandbox Error", f"Live probe execution failed: {str(e)}")
        finally:
            self.btn_run.setEnabled(True)
            self.btn_run.setText("⚡ Execute Live PoC Probe")


class AutoPatchDialog(QDialog):
    """
    Autonomous Code Auto-Patcher & Unified Git Diff Engine Dialog.
    Generates standard Unified Git Diffs (.patch) and applies safe remediations
    with automatic backup creation (.bak) and one-click rollback.
    """

    def __init__(
        self,
        parent=None,
        flaw_type: str = "SQL_INJECTION",
        flaw_id: str = "CHARLO-AUTO-PATCH",
        sample_code: str = "",
        target_file: str = "vulnerable_component.py"
    ):
        super().__init__(parent)
        self.setWindowTitle("CHARLO Autonomous Code Auto-Patcher & Unified Git Diff Engine")
        self.resize(820, 640)
        self.setStyleSheet("""
            QDialog {
                background-color: #0b0f19;
                color: #e4e9f2;
            }
            QLabel {
                color: #cbd5e1;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #12151d;
                border: 1px solid #1e2434;
                border-radius: 7px;
                padding: 6px 10px;
                color: #ffffff;
                font-size: 12.5px;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border-color: #00ff9d;
            }
        """)

        self.last_backup_file = None
        self.flaw_id = flaw_id

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header Title
        title_box = QHBoxLayout()
        icon_lbl = QLabel("✨")
        icon_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #00ff9d;")
        title_lbl = QLabel("AUTONOMOUS CODE AUTO-PATCHER")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #ffffff; letter-spacing: 0.5px;")
        sub_lbl = QLabel("Unified Git Diff (.patch) Generator")
        sub_lbl.setStyleSheet("font-size: 11px; color: #8b93a4; font-weight: 600;")
        title_box.addWidget(icon_lbl)
        title_box.addWidget(title_lbl)
        title_box.addStretch()
        title_box.addWidget(sub_lbl)
        layout.addLayout(title_box)

        # Config Bar
        cfg_frame = QFrame()
        cfg_frame.setStyleSheet("background-color: #0f1422; border: 1px solid #1a2333; border-radius: 9px;")
        cfg_layout = QGridLayout(cfg_frame)
        cfg_layout.setContentsMargins(14, 12, 14, 12)
        cfg_layout.setSpacing(8)

        # Vulnerability Rule
        cfg_layout.addWidget(QLabel("Remediation Rule:"), 0, 0)
        self.rule_combo = QComboBox()
        rules = list(AutoPatcher.REMEDIATION_RULES.keys())
        self.rule_combo.addItems(rules)
        f_upper = flaw_type.upper()
        if f_upper in rules:
            self.rule_combo.setCurrentText(f_upper)
        self.rule_combo.currentTextChanged.connect(self._recalculate_diff)
        cfg_layout.addWidget(self.rule_combo, 0, 1)

        # Target local file (optional)
        cfg_layout.addWidget(QLabel("Target File:"), 0, 2)
        f_box = QHBoxLayout()
        self.file_edit = QLineEdit(target_file)
        f_box.addWidget(self.file_edit)
        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 4px 10px; font-size: 11.5px;")
        self.btn_browse.clicked.connect(self._browse_file)
        f_box.addWidget(self.btn_browse)
        cfg_layout.addLayout(f_box, 0, 3)

        layout.addWidget(cfg_frame)

        # Splitter: Left Original Code, Right Unified Diff
        splitter = QSplitter(Qt.Horizontal)

        left_w = QFrame()
        left_layout = QVBoxLayout(left_w)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(4)
        left_layout.addWidget(QLabel("SOURCE / VULNERABLE CODE:"))
        self.src_edit = QTextEdit()
        default_sample = sample_code or 'def get_user(username):\n    query = f"SELECT * FROM users WHERE username = \'{username}\'"\n    cursor.execute(query)\n    return cursor.fetchone()\n'
        self.src_edit.setText(default_sample)
        self.src_edit.setStyleSheet("font-family: Consolas, monospace; font-size: 11px; background-color: #0b0f19;")
        self.src_edit.textChanged.connect(self._recalculate_diff)
        left_layout.addWidget(self.src_edit)
        splitter.addWidget(left_w)

        right_w = QFrame()
        right_layout = QVBoxLayout(right_w)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(4)
        right_layout.addWidget(QLabel("UNIFIED GIT DIFF (.patch):"))
        self.diff_view = QTextEdit()
        self.diff_view.setReadOnly(True)
        self.diff_view.setStyleSheet("""
            QTextEdit {
                font-family: Consolas, monospace;
                font-size: 11px;
                background-color: #06090e;
                color: #00ff9d;
                border: 1px solid #1a2333;
            }
        """)
        right_layout.addWidget(self.diff_view)
        splitter.addWidget(right_w)

        splitter.setStretchFactor(0, 1)
        splitter.setStretchFactor(1, 1)
        layout.addWidget(splitter, 1)

        # Status & Action Buttons
        self.status_lbl = QLabel("Unified diff generated automatically.")
        self.status_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        layout.addWidget(self.status_lbl)

        btn_row = QHBoxLayout()
        self.btn_copy = QPushButton("📋 Copy .patch")
        self.btn_copy.setStyleSheet("background-color: #00d4ff; color: #0b0f19; font-weight: 800; border: none; border-radius: 7px; padding: 7px 15px; font-size: 12px;")
        self.btn_copy.clicked.connect(self._copy_patch)
        btn_row.addWidget(self.btn_copy)

        self.btn_export = QPushButton("💾 Save .patch File")
        self.btn_export.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 7px; padding: 7px 14px; font-size: 12px; font-weight: 700;")
        self.btn_export.clicked.connect(self._export_patch)
        btn_row.addWidget(self.btn_export)

        self.btn_apply = QPushButton("⚡ Apply Patch to File")
        self.btn_apply.setStyleSheet("background-color: #00ff9d; color: #0b0f19; font-weight: 800; border: none; border-radius: 7px; padding: 7px 15px; font-size: 12px;")
        self.btn_apply.clicked.connect(self._apply_patch)
        btn_row.addWidget(self.btn_apply)

        self.btn_rollback = QPushButton("⏪ Rollback Backup")
        self.btn_rollback.setStyleSheet("background-color: #231217; color: #ff2a44; border: 1px solid #ff2a44; border-radius: 7px; padding: 7px 14px; font-size: 12px; font-weight: 700;")
        self.btn_rollback.setEnabled(False)
        self.btn_rollback.clicked.connect(self._rollback_patch)
        btn_row.addWidget(self.btn_rollback)

        btn_row.addStretch()

        self.btn_close = QPushButton("Close")
        self.btn_close.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 7px; padding: 7px 16px; font-size: 12px;")
        self.btn_close.clicked.connect(self.accept)
        btn_row.addWidget(self.btn_close)

        layout.addLayout(btn_row)

        self._recalculate_diff()

    def _browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Local Vulnerable File", "", "Code Files (*.py *.js *.ts *.html *.php *.sql);;All Files (*.*)"
        )
        if file_path:
            self.file_edit.setText(file_path)
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    self.src_edit.setText(f.read())
            except Exception as e:
                QMessageBox.warning(self, "Read Error", f"Unable to read selected file:\n{str(e)}")

    def _recalculate_diff(self):
        flaw_type = self.rule_combo.currentText()
        src = self.src_edit.toPlainText()
        filename = os.path.basename(self.file_edit.text().strip()) or "vulnerable_component.py"

        diff_str, desc = AutoPatcher.generate_diff(flaw_type, src, filename)
        self.diff_view.setText(diff_str)
        self.status_lbl.setText(f"Remediation Strategy: {desc}")

    def _copy_patch(self):
        diff_text = self.diff_view.toPlainText()
        if not diff_text:
            return
        QApplication.clipboard().setText(diff_text)
        self.status_lbl.setText("✅ Unified Git Diff (.patch) copied to clipboard!")

    def _export_patch(self):
        diff_text = self.diff_view.toPlainText()
        if not diff_text:
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Remediation Patch", "remediation.patch", "Git Patch Files (*.patch *.diff)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(diff_text)
            QMessageBox.information(self, "Patch Saved", f"Unified diff successfully saved to:\n{file_path}")

    def _apply_patch(self):
        path = self.file_edit.text().strip()
        if not os.path.exists(path):
            QMessageBox.warning(self, "File Not Found", f"Cannot apply patch. File does not exist on disk:\n{path}\nBrowse to a valid local file to apply changes.")
            return

        flaw_type = self.rule_combo.currentText()
        res = AutoPatcher.apply_patch(self.flaw_id, path, flaw_type)

        if res.applied:
            self.last_backup_file = res.backup_file
            self.btn_rollback.setEnabled(True)
            self.status_lbl.setText(f"✅ {res.message}")
            QMessageBox.information(self, "Patch Applied", f"{res.message}\nBackup: {res.backup_file}")
            # Refresh source view
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.src_edit.setText(f.read())
            except Exception:
                pass
        else:
            QMessageBox.critical(self, "Patch Failed", res.message)

    def _rollback_patch(self):
        if not self.last_backup_file or not os.path.exists(self.last_backup_file):
            QMessageBox.warning(self, "No Backup Found", "Backup file is missing or already rolled back.")
            return

        ok = AutoPatcher.rollback_patch(self.last_backup_file)
        if ok:
            path = self.file_edit.text().strip()
            self.status_lbl.setText(f"⏪ Successfully restored file from {os.path.basename(self.last_backup_file)}")
            self.btn_rollback.setEnabled(False)
            QMessageBox.information(self, "Rollback Complete", f"Restored original file content from backup:\n{self.last_backup_file}")
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self.src_edit.setText(f.read())
            except Exception:
                pass
        else:
            QMessageBox.critical(self, "Rollback Failed", "Could not restore original file from backup.")


class WebhookConfigDialog(QDialog):
    """
    Webhook Dispatcher Dialog for Slack, Discord, MS Teams, and Generic Webhooks.
    """

    def __init__(self, parent=None, result: Optional[ScanResult] = None):
        super().__init__(parent)
        self.setWindowTitle("CHARLO Webhook Alert Dispatcher")
        self.resize(680, 480)
        self.setStyleSheet("""
            QDialog {
                background-color: #0b0f19;
                color: #e4e9f2;
            }
            QLabel {
                color: #cbd5e1;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #12151d;
                border: 1px solid #1e2434;
                border-radius: 7px;
                padding: 6px 10px;
                color: #ffffff;
                font-size: 12.5px;
            }
            QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
                border-color: #a855f7;
            }
        """)

        self.result = result

        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Title
        title_box = QHBoxLayout()
        icon_lbl = QLabel("🔔")
        icon_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #a855f7;")
        title_lbl = QLabel("WEBHOOK ALERT & SIEM DISPATCHER")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #ffffff; letter-spacing: 0.5px;")
        sub_lbl = QLabel("Slack • Discord • MS Teams • Generic HTTP")
        sub_lbl.setStyleSheet("font-size: 11px; color: #8b93a4; font-weight: 600;")
        title_box.addWidget(icon_lbl)
        title_box.addWidget(title_lbl)
        title_box.addStretch()
        title_box.addWidget(sub_lbl)
        layout.addLayout(title_box)

        # Webhook URL Input
        layout.addWidget(QLabel("Incoming Webhook Endpoint URL:"))
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("https://hooks.slack.com/... OR https://discord.com/api/webhooks/...")
        self.url_edit.textChanged.connect(self._on_url_changed)
        layout.addWidget(self.url_edit)

        # Detected Channel Badge
        self.channel_badge = QLabel("Platform: Enter Webhook URL to Auto-Detect")
        self.channel_badge.setStyleSheet("font-size: 11px; color: #00d4ff; font-weight: 700;")
        layout.addWidget(self.channel_badge)

        # Custom alert title
        layout.addWidget(QLabel("Alert Title / Message Header:"))
        target_name = result.target.display_name if result and result.target else "Target System"
        self.title_edit = QLineEdit(f"🛡️ CHARLO Security Audit Alert: {target_name}")
        layout.addWidget(self.title_edit)

        # Status Label
        self.status_lbl = QLabel("Ready to dispatch telemetry card.")
        self.status_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4;")
        layout.addWidget(self.status_lbl)

        layout.addStretch()

        # Action Buttons
        btn_box = QHBoxLayout()
        self.btn_dispatch = QPushButton("🔔 Dispatch Alert Now")
        self.btn_dispatch.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #7c3aed, stop:1 #9333ea);
                color: #ffffff;
                font-weight: 800;
                font-size: 12.5px;
                border: none;
                border-radius: 7px;
                padding: 8px 20px;
            }
            QPushButton:hover {
                background: #8b5cf6;
            }
        """)
        self.btn_dispatch.clicked.connect(self._dispatch)
        btn_box.addWidget(self.btn_dispatch)

        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 7px; padding: 8px 16px; font-weight: 700;")
        self.btn_cancel.clicked.connect(self.reject)
        btn_box.addWidget(self.btn_cancel)

        layout.addLayout(btn_box)

    def _on_url_changed(self, url: str):
        detected = WebhookNotifier.detect_channel_type(url)
        names = {
            "slack": "Slack Incoming Webhook (Rich Attachment Card)",
            "discord": "Discord Webhook (Rich Embed Card)",
            "teams": "Microsoft Teams (MessageCard Connector)",
            "generic": "Generic SIEM / DevOps (JSON HTTP POST)"
        }
        self.channel_badge.setText(f"Platform: {names.get(detected, 'Generic')}")

    def _dispatch(self):
        url = self.url_edit.text().strip()
        if not url:
            QMessageBox.warning(self, "Missing URL", "Please enter a valid webhook URL.")
            return

        if not self.result:
            QMessageBox.warning(self, "No Scan Data", "No scan audit result is available to send.")
            return

        title = self.title_edit.text().strip()
        self.btn_dispatch.setEnabled(False)
        self.btn_dispatch.setText("⏳ Dispatching...")
        QApplication.processEvents()

        try:
            res = WebhookNotifier.dispatch_alert(url, self.result, custom_title=title)
            if res.get("success"):
                self.status_lbl.setText(f"✅ Alert dispatched! HTTP {res.get('status_code')}")
                QMessageBox.information(self, "Alert Dispatched", f"Security card successfully delivered to channel!\nHTTP Status: {res.get('status_code')}")
                self.accept()
            else:
                self.status_lbl.setText(f"❌ Dispatch failed: {res.get('message')}")
                QMessageBox.critical(self, "Delivery Failed", f"Webhook delivery returned an error:\n{res.get('message')}")
        finally:
            self.btn_dispatch.setEnabled(True)
            self.btn_dispatch.setText("🔔 Dispatch Alert Now")
