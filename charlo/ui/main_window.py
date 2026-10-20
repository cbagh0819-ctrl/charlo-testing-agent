"""
Main Desktop Workstation for CHARLO Testing Agent.
Ultra-sleek Cyber Crimson & Obsidian AI security laboratory interface.
"""

import os
import sys
from typing import Optional, Any, Union, Dict, List

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QPushButton, QStackedWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QLineEdit, QComboBox, QTextEdit, QProgressBar,
    QFileDialog, QMessageBox, QFrame, QSplitter, QScrollArea,
    QButtonGroup, QRadioButton, QGraphicsDropShadowEffect, QTabWidget,
    QApplication, QSpinBox
)
from PySide6.QtGui import QIcon, QFont, QColor, QShortcut, QKeySequence

from ..core.models import (
    TargetType, ScanLevel, Severity, CheckStatus, ScanResult, CheckFinding
)
from ..core.engine import ScanEngine
from ..core.scoring import RiskCalculator
from ..core.threat_model import ThreatModelGenerator
from ..database.storage import ScanDatabase
from ..reporting.html_reporter import HTMLReporter
from ..reporting.json_reporter import JSONReporter
from ..analyzers.web_history import WebHistoryAnalyzer
from ..analyzers.attack_simulator import AttackResilienceSimulator
from ..analyzers.automation_tools import PopularToolsAutomationTester, AutomationReport
from ..analyzers.api_tester import ApiTester, ApiTestReport
from ..analyzers.performance_tester import PerformanceTester, PerformanceTestReport
from ..analyzers.cicd_generator import CiCdGenerator, QualityGateRule, QualityGateResult, CiCdPipelineReport
from ..analyzers.database_tester import DatabaseTester, DbTableInspection, DbDefect, DatabaseTestReport
from ..analyzers.compatibility_tester import CompatibilityTester, ViewportDevice, A11yDefect, CompatibilityReport
from ..analyzers.network_tester import (
    NetworkTester, TlsCipherInspection, CertificateInspection, DnsSecMailSecurity, NetworkDefect, NetworkTestReport
)
from ..analyzers.business_logic_tester import (
    BusinessLogicTester, BusinessWorkflowStep, BusinessLogicFlaw, BusinessLogicReport
)
from ..analyzers.memory_tester import (
    MemoryLeakTester, ResourceLeakDefect, MemoryProfileMetrics, MemoryLeakReport
)
from ..analyzers.accessibility_tester import (
    AccessibilityTester, AccessibilityCriterionDefect, AriaLandmark, AccessibilityMetrics, AccessibilityReport
)
from ..reporting.sarif_reporter import SarifReporter
from ..core.auto_patcher import AutoPatcher
from ..core.poc_runner import PocRunner
from ..core.webhook_notifier import WebhookNotifier
from .styles import WORKSTATION_STYLE
from .components import (
    OrbLogoWidget, SecurityPulseWidget, ToggleSwitch, TargetTypeCard, SidebarItemWidget
)
from .dialogs import PoCSandboxDialog, AutoPatchDialog, WebhookConfigDialog


class ScanWorker(QThread):
    """
    Background worker thread running scans asynchronously to keep the UI fluid.
    """
    progress_signal = Signal(int, str)
    log_signal = Signal(str)
    finished_signal = Signal(object)
    error_signal = Signal(str)

    def __init__(self, target_input: str, target_type: Any, level: Any, bugs_only: bool = False):
        super().__init__()
        self.target_input = target_input
        self.target_type = TargetType.from_string(target_type) if isinstance(target_type, str) else target_type
        self.level = ScanLevel.from_string(level) if isinstance(level, str) else level
        self.bugs_only = bugs_only

    def run(self):
        try:
            result = ScanEngine.run_scan(
                target_input=self.target_input,
                target_type=self.target_type,
                level=self.level,
                progress_callback=lambda p, m: self.progress_signal.emit(p, m),
                log_callback=lambda l: self.log_signal.emit(l),
                bugs_only=self.bugs_only,
            )
            self.finished_signal.emit(result)
        except Exception as e:
            self.error_signal.emit(str(e))


class MainWindow(QMainWindow):
    """
    CHARLO Testing Agent - Primary Desktop GUI Workstation.
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("CHARLO Testing Agent — AI-Powered Security Testing Laboratory")
        self.resize(1340, 860)
        self.setMinimumSize(1100, 720)
        self.setStyleSheet(WORKSTATION_STYLE)

        self.db = ScanDatabase()
        self.current_result: Optional[ScanResult] = None
        self.worker: Optional[ScanWorker] = None
        self._requested_attack_tab = False
        self._requested_bug_tab = False

        self._sidebar_items: List[SidebarItemWidget] = []
        self._top_pill_btns: List[QPushButton] = []
        self._selected_target_type = TargetType.WEB

        self._init_ui()
        self._setup_shortcuts()
        self._load_history()
        self._update_right_telemetry_defaults()

    def _setup_shortcuts(self):
        """Register global accessibility and productivity hotkeys."""
        self._sc_a11y = QShortcut(QKeySequence("Alt+A"), self)
        self._sc_a11y.activated.connect(lambda: self._switch_page(17))

        self._sc_logic = QShortcut(QKeySequence("Alt+L"), self)
        self._sc_logic.activated.connect(lambda: self._switch_page(15))

        self._sc_compat = QShortcut(QKeySequence("Alt+V"), self)
        self._sc_compat.activated.connect(lambda: self._switch_page(13))

        self._sc_qa = QShortcut(QKeySequence("Alt+Q"), self)
        self._sc_qa.activated.connect(lambda: self._switch_page(8))

        self._sc_home = QShortcut(QKeySequence("Alt+H"), self)
        self._sc_home.activated.connect(lambda: self._switch_page(0))

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ---------------------------------------------------------------------
        # 1. HEADER BAR
        # ---------------------------------------------------------------------
        header = QFrame()
        header.setObjectName("HeaderBar")
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(20, 10, 20, 10)
        header_layout.setSpacing(18)

        # Left Logo & Brand
        brand_layout = QHBoxLayout()
        brand_layout.setSpacing(10)
        self.orb_logo = OrbLogoWidget(size=40)
        brand_layout.addWidget(self.orb_logo)

        title_vbox = QVBoxLayout()
        title_vbox.setSpacing(0)
        title_label = QLabel("CHARLO TESTING AGENT")
        title_label.setObjectName("AppTitle")
        sub_label = QLabel("AI SECURITY TESTING LAB")
        sub_label.setObjectName("AppSubtitle")
        title_vbox.addWidget(title_label)
        title_vbox.addWidget(sub_label)
        brand_layout.addLayout(title_vbox)
        header_layout.addLayout(brand_layout)

        # Center Floating Pill Nav in Horizontal Scroll Area to prevent squeezing/overlapping
        self.top_pill_scroll = QScrollArea()
        self.top_pill_scroll.setWidgetResizable(True)
        self.top_pill_scroll.setFixedHeight(36)
        self.top_pill_scroll.setFrameShape(QFrame.NoFrame)
        self.top_pill_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.top_pill_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.top_pill_scroll.setStyleSheet("""
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollBar:horizontal {
                height: 3px;
                background: transparent;
            }
            QScrollBar::handle:horizontal {
                background: #252d40;
                border-radius: 1px;
            }
            QScrollBar::handle:horizontal:hover {
                background: #ff2a44;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
        """)

        top_pill_frame = QFrame()
        top_pill_frame.setObjectName("TopNavPillBar")
        top_pill_frame.setStyleSheet("""
            #TopNavPillBar {
                background-color: #10141e;
                border: 1px solid #1c2230;
                border-radius: 14px;
            }
        """)
        top_pill_layout = QHBoxLayout(top_pill_frame)
        top_pill_layout.setContentsMargins(4, 2, 4, 2)
        top_pill_layout.setSpacing(2)

        nav_tabs = [
            ("⊞ Scan", 0),
            ("〰 Live", 1),
            ("📊 Threats", 2),
            ("📋 Findings", 3),
            ("🐞 Bugs", 4),
            ("🌐 Intel", 5),
            ("⚔️ Attacks", 6),
            ("⏱️ History", 7),
            ("🧪 QA", 8),
            ("⚡ API", 9),
            ("📈 Perf", 10),
            ("🚀 CI/CD", 11),
            ("🗄️ Database", 12),
            ("📱 Viewport", 13),
            ("🔐 Network", 14),
            ("💼 Logic", 15),
            ("🧠 Memory", 16),
            ("♿ A11y", 17),
        ]
        for label, idx in nav_tabs:
            btn = QPushButton(label)
            btn.setProperty("class", "PillNavBtn")
            btn.setStyleSheet("""
                QPushButton {
                    background-color: transparent;
                    color: #8b93a4;
                    border: none;
                    border-radius: 11px;
                    padding: 3px 8px;
                    font-size: 11px;
                    font-weight: 700;
                }
                QPushButton:hover {
                    color: #ffffff;
                    background-color: #1a1e2a;
                }
            """)
            min_w = btn.fontMetrics().horizontalAdvance(label) + 16
            btn.setMinimumWidth(min_w)
            btn.setFixedHeight(24)
            btn.clicked.connect(lambda _, i=idx: self._switch_page(i))
            self._top_pill_btns.append(btn)
            top_pill_layout.addWidget(btn)

        self.top_pill_scroll.setWidget(top_pill_frame)
        header_layout.addWidget(self.top_pill_scroll, stretch=1)

        # Right Status / Window controls
        right_hdr = QHBoxLayout()
        right_hdr.setSpacing(10)
        self.status_badge = QLabel("● LAB READY")
        self.status_badge.setStyleSheet("""
            background-color: #231217;
            color: #ff2a44;
            border: 1px solid #ff2a44;
            border-radius: 12px;
            padding: 4px 12px;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 0.5px;
        """)
        right_hdr.addWidget(self.status_badge)
        header_layout.addLayout(right_hdr)

        main_layout.addWidget(header)

        # ---------------------------------------------------------------------
        # 2. BODY: 3-COLUMN WORKSPACE
        # ---------------------------------------------------------------------
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(14, 14, 14, 14)
        body_layout.setSpacing(14)

        # === COLUMN A: LEFT SIDEBAR NAVIGATION WITH SCROLL WRAPPER ===
        self.sidebar_scroll = QScrollArea()
        self.sidebar_scroll.setWidgetResizable(True)
        self.sidebar_scroll.setFixedWidth(226)
        self.sidebar_scroll.setFrameShape(QFrame.NoFrame)
        self.sidebar_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.sidebar_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.sidebar_scroll.setStyleSheet("""
            QScrollArea {
                background-color: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background: #090c13;
                width: 4px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #1f2738;
                min-height: 20px;
                border-radius: 2px;
            }
            QScrollBar::handle:vertical:hover {
                background: #ff2a44;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)

        self.sidebar_frame = QFrame()
        self.sidebar_frame.setObjectName("PanelBox")
        self.sidebar_frame.setStyleSheet("#PanelBox { background-color: #0d1017; border: 1px solid #1c2230; border-radius: 12px; }")
        sidebar_layout = QVBoxLayout(self.sidebar_frame)
        sidebar_layout.setContentsMargins(6, 8, 6, 8)
        sidebar_layout.setSpacing(3)

        sidebar_defs = [
            ("🏠", "New Scan", "Start a security test", 0),
            ("〰️", "Live Progress", "Real-time scanning", 1),
            ("📊", "Threat Analysis", "AI-powered insights", 2),
            ("📋", "Technical Findings", "Detailed reports", 3),
            ("🐞", "Bug Finder", "Discover vulnerabilities", 4),
            ("🌐", "Website History", "Visited & scanned", 5),
            ("⚔️", "Test a Hack", "Attack resilience sim", 6),
            ("⏱️", "Scan History", "Previous results", 7),
            ("🧪", "QA Automation", "Playwright, Appium, WinApp", 8),
            ("⚡", "API Testing", "Contract, fuzzing, postman", 9),
            ("📈", "Load Testing", "JMeter, k6, concurrency", 10),
            ("🚀", "CI/CD & Gates", "GitHub, GitLab, Jenkins", 11),
            ("🗄️", "Database QA", "Schema, indexes, SQL", 12),
            ("📱", "Responsive Viewports", "Multi-device layout", 13),
            ("🔐", "Network & TLS", "Protocols, ciphers, certs", 14),
            ("💼", "Business Logic", "State machine, flows", 15),
            ("🧠", "Memory QA", "Leaks, handles, heap", 16),
            ("♿", "Accessibility QA", "WCAG 2.2, VPAT, ARIA", 17),
        ]

        for icon_s, title_s, sub_s, page_i in sidebar_defs:
            item = SidebarItemWidget(icon_s, title_s, sub_s, is_active=(page_i == 0))
            item.clicked.connect(lambda i=page_i: self._switch_page(i))
            self._sidebar_items.append(item)
            sidebar_layout.addWidget(item)

        sidebar_layout.addStretch()
        self.sidebar_scroll.setWidget(self.sidebar_frame)
        body_layout.addWidget(self.sidebar_scroll)

        # === COLUMN B: MAIN STACKED CONTENT AREA ===
        self.pages = QStackedWidget()
        body_layout.addWidget(self.pages, stretch=1)

        # Build each individual page
        self.page_new_scan = QWidget()
        self.page_progress = QWidget()
        self.page_threat = QWidget()
        self.page_findings = QWidget()
        self.page_bugs = QWidget()
        self.page_web_history = QWidget()
        self.page_attacks = QWidget()
        self.page_history = QWidget()
        self.page_automation = QWidget()
        self.page_api = QWidget()
        self.page_perf = QWidget()
        self.page_cicd = QWidget()
        self.page_db = QWidget()
        self.page_compat = QWidget()
        self.page_network = QWidget()
        self.page_logic = QWidget()
        self.page_memory = QWidget()
        self.page_a11y = QWidget()

        self.pages.addWidget(self.page_new_scan)      # index 0
        self.pages.addWidget(self.page_progress)      # index 1
        self.pages.addWidget(self.page_threat)        # index 2
        self.pages.addWidget(self.page_findings)      # index 3
        self.pages.addWidget(self.page_bugs)          # index 4
        self.pages.addWidget(self.page_web_history)  # index 5
        self.pages.addWidget(self.page_attacks)      # index 6
        self.pages.addWidget(self.page_history)      # index 7
        self.pages.addWidget(self.page_automation)   # index 8
        self.pages.addWidget(self.page_api)          # index 9
        self.pages.addWidget(self.page_perf)         # index 10
        self.pages.addWidget(self.page_cicd)         # index 11
        self.pages.addWidget(self.page_db)           # index 12
        self.pages.addWidget(self.page_compat)       # index 13
        self.pages.addWidget(self.page_network)      # index 14
        self.pages.addWidget(self.page_logic)        # index 15
        self.pages.addWidget(self.page_memory)       # index 16
        self.pages.addWidget(self.page_a11y)         # index 17

        self._setup_new_scan_page()
        self._setup_progress_page()
        self._setup_threat_page()
        self._setup_findings_page()
        self._setup_bugs_page()
        self._setup_web_history_page()
        self._setup_attacks_page()
        self._setup_history_page()
        self._setup_automation_page()
        self._setup_api_page()
        self._setup_perf_page()
        self._setup_cicd_page()
        self._setup_db_page()
        self._setup_compat_page()
        self._setup_network_page()
        self._setup_logic_page()
        self._setup_memory_page()
        self._setup_a11y_page()

        # === COLUMN C: RIGHT TELEMETRY & SECURITY PULSE ===
        self.telemetry_frame = QFrame()
        self.telemetry_frame.setObjectName("PanelBox")
        self.telemetry_frame.setFixedWidth(250)
        tele_layout = QVBoxLayout(self.telemetry_frame)
        tele_layout.setContentsMargins(14, 14, 14, 14)
        tele_layout.setSpacing(12)

        # 1. System Status Box
        sys_status_card = QFrame()
        sys_status_card.setObjectName("SysStatusCard")
        sys_status_card.setStyleSheet("""
            #SysStatusCard {
                background-color: #12151d;
                border: 1px solid #1c2230;
                border-radius: 10px;
            }
        """)
        ss_layout = QVBoxLayout(sys_status_card)
        ss_layout.setContentsMargins(10, 8, 10, 8)
        ss_layout.setSpacing(6)

        ss_header = QHBoxLayout()
        ss_title = QLabel("System Status")
        ss_title.setStyleSheet("border: none; background: transparent; font-size: 13px; font-weight: 700; color: #ffffff;")
        self.ss_dot_lbl = QLabel("● All Systems Online")
        self.ss_dot_lbl.setStyleSheet("border: none; background: transparent; font-size: 11px; color: #ff2a44; font-weight: 700;")
        ss_header.addWidget(ss_title)
        ss_header.addStretch()
        ss_layout.addLayout(ss_header)
        ss_layout.addWidget(self.ss_dot_lbl)

        # 3 mini stat cards
        mini_stats_row = QHBoxLayout()
        mini_stats_row.setSpacing(6)

        def make_mini_box(val, label, icon):
            b = QFrame()
            b.setObjectName("MiniBox")
            b.setStyleSheet("""
                #MiniBox {
                    background-color: #0b0d12;
                    border: 1px solid #1a202c;
                    border-radius: 8px;
                }
            """)
            l = QVBoxLayout(b)
            l.setContentsMargins(2, 6, 2, 6)
            l.setSpacing(2)
            l.setAlignment(Qt.AlignCenter)

            ic_lbl = QLabel(icon)
            ic_lbl.setStyleSheet("border: none; background: transparent; font-size: 15px;")
            ic_lbl.setAlignment(Qt.AlignCenter)

            v_lbl = QLabel(val)
            v_lbl.setStyleSheet("border: none; background: transparent; font-size: 13px; font-weight: 800; color: #ffffff;")
            v_lbl.setAlignment(Qt.AlignCenter)

            s_lbl = QLabel(label)
            s_lbl.setStyleSheet("border: none; background: transparent; font-size: 9.5px; color: #7b8497; text-transform: uppercase; font-weight: 600;")
            s_lbl.setAlignment(Qt.AlignCenter)

            l.addWidget(ic_lbl)
            l.addWidget(v_lbl)
            l.addWidget(s_lbl)
            b.v_lbl = v_lbl
            return b

        self.box_active_scans = make_mini_box("0", "Active", "〰️")
        self.box_test_modules = make_mini_box("100+", "Checks", "⊞")
        self.box_ai_agent = make_mini_box("Online", "AI Core", "🧠")

        mini_stats_row.addWidget(self.box_active_scans)
        mini_stats_row.addWidget(self.box_test_modules)
        mini_stats_row.addWidget(self.box_ai_agent)
        ss_layout.addLayout(mini_stats_row)
        tele_layout.addWidget(sys_status_card)

        # 2. Security Pulse Card (Radar)
        pulse_card = QFrame()
        pulse_card.setObjectName("PulseCard")
        pulse_card.setStyleSheet("""
            #PulseCard {
                background-color: #12151d;
                border: 1px solid #1c2230;
                border-radius: 10px;
            }
        """)
        pc_layout = QVBoxLayout(pulse_card)
        pc_layout.setContentsMargins(10, 8, 10, 8)
        pc_layout.setSpacing(6)

        pc_header = QHBoxLayout()
        pc_title = QLabel("Security Pulse")
        pc_title.setStyleSheet("border: none; background: transparent; font-size: 13px; font-weight: 700; color: #ffffff;")
        live_tag = QLabel("● LIVE")
        live_tag.setStyleSheet("background-color: #3b141b; color: #ff2a44; font-size: 9.5px; font-weight: 800; padding: 2px 7px; border-radius: 4px; border: 1px solid #5a1924;")
        pc_header.addWidget(pc_title)
        pc_header.addStretch()
        pc_header.addWidget(live_tag)
        pc_layout.addLayout(pc_header)

        # Concentric Radar Widget
        self.radar_widget = SecurityPulseWidget()
        pc_layout.addWidget(self.radar_widget, alignment=Qt.AlignCenter)

        # Real-time Metrics 2x2 Grid (Compact Chips)
        grid_metrics = QGridLayout()
        grid_metrics.setSpacing(6)

        def make_chip(text, color):
            lbl = QLabel(text)
            lbl.setAlignment(Qt.AlignCenter)
            lbl.setFixedHeight(24)
            lbl.setStyleSheet(f"""
                QLabel {{
                    background-color: #0b0d13;
                    color: {color};
                    border: 1px solid #1a202c;
                    border-radius: 6px;
                    padding: 0px 4px;
                    font-size: 10.5px;
                    font-weight: 800;
                }}
            """)
            return lbl

        self.metric_threats_lbl = make_chip("0 Threats", "#ff2a44")
        self.metric_vulns_lbl = make_chip("0 Vulns", "#ffb800")
        self.metric_suspicious_lbl = make_chip("0 Defects", "#a855f7")
        self.metric_score_lbl = make_chip("-- Score", "#00d4ff")

        grid_metrics.addWidget(self.metric_threats_lbl, 0, 0)
        grid_metrics.addWidget(self.metric_vulns_lbl, 0, 1)
        grid_metrics.addWidget(self.metric_suspicious_lbl, 1, 0)
        grid_metrics.addWidget(self.metric_score_lbl, 1, 1)

        pc_layout.addLayout(grid_metrics)
        tele_layout.addWidget(pulse_card)

        # 3. Recent Activity Box
        recent_card = QFrame()
        recent_card.setObjectName("RecentCard")
        recent_card.setStyleSheet("""
            #RecentCard {
                background-color: #12151d;
                border: 1px solid #1c2230;
                border-radius: 10px;
            }
        """)
        rc_layout = QVBoxLayout(recent_card)
        rc_layout.setContentsMargins(10, 8, 10, 8)
        rc_layout.setSpacing(6)

        rc_header = QHBoxLayout()
        rc_title = QLabel("Recent Activity")
        rc_title.setStyleSheet("border: none; background: transparent; font-size: 13px; font-weight: 700; color: #ffffff;")
        self.rc_badge = QLabel("No scans yet")
        self.rc_badge.setStyleSheet("border: none; background: transparent; font-size: 11px; color: #7b8497;")
        rc_header.addWidget(rc_title)
        rc_header.addStretch()
        rc_header.addWidget(self.rc_badge)
        rc_layout.addLayout(rc_header)

        self.recent_desc_lbl = QLabel("Run a security scan to see live progress, findings and analysis here.")
        self.recent_desc_lbl.setStyleSheet("""
            QLabel {
                background-color: #0b0d13;
                border: 1px solid #1a202c;
                border-radius: 8px;
                padding: 6px 8px;
                font-size: 11.5px;
                color: #8b93a4;
                line-height: 1.35;
            }
        """)
        self.recent_desc_lbl.setWordWrap(True)
        rc_layout.addWidget(self.recent_desc_lbl)

        tele_layout.addWidget(recent_card)
        tele_layout.addStretch()

        body_layout.addWidget(self.telemetry_frame)
        main_layout.addWidget(body_widget)

        # Select initial page
        self._switch_page(0)

    # =========================================================================
    # NAVIGATION LOGIC
    # =========================================================================
    def _switch_page(self, index: int):
        self.pages.setCurrentIndex(index)
        # Update sidebar
        for i, item in enumerate(self._sidebar_items):
            item.setActive(i == index)
        # Update top pills
        for i, btn in enumerate(self._top_pill_btns):
            if i == index:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: #ff2a44;
                        color: #ffffff;
                        border: none;
                        border-radius: 11px;
                        padding: 3px 8px;
                        font-size: 11px;
                        font-weight: 800;
                    }
                """)
            else:
                btn.setStyleSheet("""
                    QPushButton {
                        background-color: transparent;
                        color: #8b93a4;
                        border: none;
                        border-radius: 11px;
                        padding: 3px 8px;
                        font-size: 11px;
                        font-weight: 700;
                    }
                    QPushButton:hover {
                        color: #ffffff;
                        background-color: #1a1e2a;
                    }
                """)
        if hasattr(self, "top_pill_scroll") and index < len(self._top_pill_btns):
            self.top_pill_scroll.ensureWidgetVisible(self._top_pill_btns[index])
        if hasattr(self, "sidebar_scroll") and index < len(self._sidebar_items):
            self.sidebar_scroll.ensureWidgetVisible(self._sidebar_items[index])

    # =========================================================================
    # PAGE 0: NEW SECURITY SCAN (MATCHING SCREENSHOT)
    # =========================================================================
    def _setup_new_scan_page(self):
        scroll = QScrollArea(self.page_new_scan)
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(10, 8, 10, 10)
        layout.setSpacing(16)

        # 1. SELECT TARGET TYPE HEADER
        sel_hdr = QHBoxLayout()
        sel_title = QLabel("Select Target Type")
        sel_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #ffffff;")
        sel_sub = QLabel("Choose what you want to test ➔")
        sel_sub.setStyleSheet("font-size: 12px; color: #7b8497; font-weight: 600;")
        sel_hdr.addWidget(sel_title)
        sel_hdr.addStretch()
        sel_hdr.addWidget(sel_sub)
        layout.addLayout(sel_hdr)

        # 3. 3 TARGET TYPE CARDS
        cards_row = QHBoxLayout()
        cards_row.setSpacing(12)

        self.card_apk = TargetTypeCard(
            icon_text="🤖",
            title="Android Application",
            subtitle="(.apk)",
            description="Analyze Android apps for malware, permissions, risks",
            is_selected=False,
        )
        self.card_exe = TargetTypeCard(
            icon_text="🪟",
            title="Windows Executable",
            subtitle="(.exe, .dll)",
            description="Scan Windows files for malware and vulnerabilities",
            is_selected=False,
        )
        self.card_web = TargetTypeCard(
            icon_text="🌐",
            title="Authorized Website URL",
            subtitle="(https://)",
            description="Test websites for vulnerabilities and security issues",
            is_selected=True,  # Default
        )

        self.card_apk.clicked.connect(lambda: self._select_target_type(TargetType.APK))
        self.card_exe.clicked.connect(lambda: self._select_target_type(TargetType.EXE))
        self.card_web.clicked.connect(lambda: self._select_target_type(TargetType.WEB))

        cards_row.addWidget(self.card_apk)
        cards_row.addWidget(self.card_exe)
        cards_row.addWidget(self.card_web)
        layout.addLayout(cards_row)

        # 4. TARGET URL / FILE PATH INPUT
        input_box = QFrame()
        input_box.setObjectName("CardFrame")
        ib_layout = QVBoxLayout(input_box)
        ib_layout.setContentsMargins(16, 14, 16, 14)
        ib_layout.setSpacing(8)

        target_lbl = QLabel("Target URL / File Path")
        target_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #8b93a4; text-transform: uppercase; letter-spacing: 0.5px;")
        ib_layout.addWidget(target_lbl)

        input_row = QHBoxLayout()
        input_row.setSpacing(8)

        self.target_icon_btn = QPushButton("🌐")
        self.target_icon_btn.setFixedSize(38, 38)
        self.target_icon_btn.setStyleSheet("background-color: #171c28; border: 1px solid #232a3d; border-radius: 8px; font-size: 16px;")
        self.target_icon_btn.clicked.connect(self._browse_file)
        input_row.addWidget(self.target_icon_btn)

        self.target_path_edit = QLineEdit()
        self.target_path_edit.setPlaceholderText("Enter target domain or URL (e.g., https://example.com)")
        self.target_path_edit.setText("https://pmec.ac.in")
        self.target_path_edit.setMinimumHeight(40)
        self.target_path_edit.setStyleSheet("font-size: 13.5px; padding-left: 10px;")
        input_row.addWidget(self.target_path_edit, stretch=1)

        self.btn_clear_input = QPushButton("✕")
        self.btn_clear_input.setFixedSize(38, 38)
        self.btn_clear_input.setStyleSheet("background-color: #171c28; border: 1px solid #232a3d; border-radius: 8px; font-size: 13px; color: #8b93a4;")
        self.btn_clear_input.clicked.connect(lambda: self.target_path_edit.clear())
        input_row.addWidget(self.btn_clear_input)

        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.setMinimumHeight(38)
        self.btn_browse.setStyleSheet("background-color: #1b202d; color: #e4e9f2; border: 1px solid #2c3548; font-weight: 700;")
        self.btn_browse.clicked.connect(self._browse_file)
        input_row.addWidget(self.btn_browse)

        ib_layout.addLayout(input_row)

        self.scope_note = QLabel("⚠️ Notice: Target scanning must be restricted to applications, executables, and domains you own or are explicitly authorized to audit.")
        self.scope_note.setStyleSheet("font-size: 11px; color: #7b8497; font-style: italic;")
        ib_layout.addWidget(self.scope_note)

        layout.addWidget(input_box)

        # 5. AUDIT LEVEL, SCAN OPTIONS & TOGGLE ROW
        config_box = QFrame()
        config_box.setObjectName("CardFrame")
        cfg_layout = QHBoxLayout(config_box)
        cfg_layout.setContentsMargins(16, 12, 16, 12)
        cfg_layout.setSpacing(14)

        # Audit Level
        v_lvl = QVBoxLayout()
        v_lvl.setSpacing(4)
        lbl_l = QLabel("🛡️ Audit Level")
        lbl_l.setStyleSheet("font-size: 11.5px; font-weight: 700; color: #8b93a4;")
        self.level_combo = QComboBox()
        self.level_combo.addItem("Basic Audit - Essential perimeter checks", ScanLevel.BASIC)
        self.level_combo.addItem("Intermediate Audit - Full heuristics & defects", ScanLevel.INTERMEDIATE)
        self.level_combo.addItem("Advanced Audit - Exhaustive deep inspection", ScanLevel.ADVANCED)
        self.level_combo.setCurrentIndex(1)
        self.level_combo.setMinimumHeight(36)
        v_lvl.addWidget(lbl_l)
        v_lvl.addWidget(self.level_combo)
        cfg_layout.addLayout(v_lvl, stretch=1)

        # Scan Profile Options
        v_opt = QVBoxLayout()
        v_opt.setSpacing(4)
        lbl_o = QLabel("🎛️ Scan Options")
        lbl_o.setStyleSheet("font-size: 11.5px; font-weight: 700; color: #8b93a4;")
        self.options_combo = QComboBox()
        self.options_combo.addItem("Default Scan Profile (Recommended)")
        self.options_combo.addItem("High-Velocity Perimeter Audit")
        self.options_combo.addItem("Deep Static Bytecode & Forensic Catalog")
        self.options_combo.setMinimumHeight(36)
        v_opt.addWidget(lbl_o)
        v_opt.addWidget(self.options_combo)
        cfg_layout.addLayout(v_opt, stretch=1)

        # Enable Deep AI Analysis Toggle
        toggle_box = QHBoxLayout()
        toggle_box.setSpacing(10)
        self.ai_toggle = ToggleSwitch(checked=True)
        toggle_box.addWidget(self.ai_toggle)

        t_text = QVBoxLayout()
        t_text.setSpacing(1)
        t_title = QLabel("Enable Deep AI Analysis")
        t_title.setStyleSheet("font-size: 12.5px; font-weight: 700; color: #ffffff;")
        t_sub = QLabel("Use AI for advanced threat detection")
        t_sub.setStyleSheet("font-size: 10.5px; color: #7b8497;")
        t_text.addWidget(t_title)
        t_text.addWidget(t_sub)
        toggle_box.addLayout(t_text)

        cfg_layout.addLayout(toggle_box)
        layout.addWidget(config_box)

        # 6. ACTION BUTTONS (2-BUTTON PRIMARY ROW MATCHING DESIGN)
        action_row = QHBoxLayout()
        action_row.setSpacing(14)

        self.start_btn = QPushButton("▶  Start Security Scan        FIND THREATS")
        self.start_btn.setObjectName("PrimaryRedBtn")
        self.start_btn.setMinimumHeight(52)
        self.start_btn.clicked.connect(lambda: self._start_scan(bugs_only=False))
        action_row.addWidget(self.start_btn, stretch=3)

        self.start_bug_btn = QPushButton("🐞  Run Dedicated Bug Audit ➔")
        self.start_bug_btn.setObjectName("SecondaryDarkBtn")
        self.start_bug_btn.setMinimumHeight(52)
        self.start_bug_btn.clicked.connect(lambda: self._start_scan(bugs_only=True))
        action_row.addWidget(self.start_bug_btn, stretch=2)

        self.start_a11y_btn = QPushButton("♿  Run Accessibility & VPAT Audit ➔")
        self.start_a11y_btn.setMinimumHeight(52)
        self.start_a11y_btn.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0d1e34, stop:1 #0b1728);
                color: #38bdf8;
                border: 1px solid #0284c7;
                font-weight: 800;
                border-radius: 10px;
                padding: 10px 18px;
                font-size: 13px;
                letter-spacing: 0.3px;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #132a48, stop:1 #0e1e35);
                border-color: #38bdf8;
                color: #ffffff;
            }
            QPushButton:pressed {
                background: #081321;
            }
        """)
        self.start_a11y_btn.setToolTip("Run automated WCAG 2.2 / Section 508 accessibility audit on target (Shortcut: Alt+A)")
        self.start_a11y_btn.clicked.connect(lambda: self._start_scan(open_a11y=True))
        action_row.addWidget(self.start_a11y_btn, stretch=2)

        # Retain start_atk_btn reference for API & test compatibility (accessible via Attacks sidebar)
        self.start_atk_btn = QPushButton("⚔️  Test a Hack (Threat Simulator) ➔")
        self.start_atk_btn.setObjectName("SecondaryDarkBtn")
        self.start_atk_btn.clicked.connect(lambda: self._start_scan(open_attacks=True))
        self.start_atk_btn.hide()
        action_row.addWidget(self.start_atk_btn)

        self.start_qa_btn = QPushButton("🧪  Run QA Automation Suite ➔")
        self.start_qa_btn.setObjectName("SecondaryDarkBtn")
        self.start_qa_btn.clicked.connect(lambda: self._start_scan(open_qa=True))
        self.start_qa_btn.hide()
        action_row.addWidget(self.start_qa_btn)

        layout.addLayout(action_row)

        # 7. WORKSTATION SHORTCUTS & SPECIALIZED AUDITS PANEL
        shortcuts_box = QFrame()
        shortcuts_box.setObjectName("CardFrame")
        sc_box_layout = QVBoxLayout(shortcuts_box)
        sc_box_layout.setContentsMargins(16, 14, 16, 14)
        sc_box_layout.setSpacing(12)

        sc_hdr = QHBoxLayout()
        sc_title = QLabel("⚡ Specialized Testing Workbenches & Quick Shortcuts")
        sc_title.setStyleSheet("font-size: 13px; font-weight: 800; color: #ffffff; letter-spacing: 0.5px;")
        sc_sub = QLabel("1-Click Direct Launch or Workbench Navigation")
        sc_sub.setStyleSheet("font-size: 11px; color: #7b8497; font-weight: 600;")
        sc_hdr.addWidget(sc_title)
        sc_hdr.addStretch()
        sc_hdr.addWidget(sc_sub)
        sc_box_layout.addLayout(sc_hdr)

        # 4 Interactive Shortcut Cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        # Card 1: Accessibility & VPAT (Featured Highlight)
        card_a11y = QFrame()
        card_a11y.setStyleSheet("""
            QFrame {
                background-color: #0b1523;
                border: 1px solid #0284c7;
                border-radius: 10px;
            }
            QFrame:hover {
                background-color: #0f1c30;
                border-color: #38bdf8;
            }
        """)
        c_a11y_layout = QVBoxLayout(card_a11y)
        c_a11y_layout.setContentsMargins(12, 10, 12, 10)
        c_a11y_layout.setSpacing(6)

        c_a11y_top = QHBoxLayout()
        lbl_a11y_icon = QLabel("♿ Accessibility QA")
        lbl_a11y_icon.setStyleSheet("font-size: 13px; font-weight: 800; color: #38bdf8;")
        pill_a11y = QLabel("Alt+A")
        pill_a11y.setStyleSheet("background: #0369a1; color: #ffffff; font-size: 9.5px; font-weight: 800; padding: 2px 6px; border-radius: 4px;")
        c_a11y_top.addWidget(lbl_a11y_icon)
        c_a11y_top.addStretch()
        c_a11y_top.addWidget(pill_a11y)
        c_a11y_layout.addLayout(c_a11y_top)

        lbl_a11y_sub = QLabel("WCAG 2.2 • Section 508 • VPAT 2.4")
        lbl_a11y_sub.setStyleSheet("font-size: 10px; font-weight: 700; color: #7dd3fc;")
        c_a11y_layout.addWidget(lbl_a11y_sub)

        lbl_a11y_desc = QLabel("ARIA tree, contrast ratios, keyboard traps & official compliance reports.")
        lbl_a11y_desc.setStyleSheet("font-size: 10.5px; color: #94a3b8; line-height: 1.2;")
        lbl_a11y_desc.setWordWrap(True)
        c_a11y_layout.addWidget(lbl_a11y_desc)
        c_a11y_layout.addStretch()

        self.btn_hp_open_a11y = QPushButton("Open Workbench ➔")
        self.btn_hp_open_a11y.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 10px; font-size: 11px;")
        self.btn_hp_open_a11y.clicked.connect(lambda: self._switch_page(17))
        c_a11y_layout.addWidget(self.btn_hp_open_a11y)

        cards_layout.addWidget(card_a11y, stretch=1)

        # Card 2: Business Logic & State Machines
        card_logic = QFrame()
        card_logic.setStyleSheet("""
            QFrame {
                background-color: #12101f;
                border: 1px solid #2e1d4d;
                border-radius: 10px;
            }
            QFrame:hover {
                background-color: #18152b;
                border-color: #a855f7;
            }
        """)
        c_logic_layout = QVBoxLayout(card_logic)
        c_logic_layout.setContentsMargins(12, 10, 12, 10)
        c_logic_layout.setSpacing(6)

        c_logic_top = QHBoxLayout()
        lbl_logic_icon = QLabel("💼 Business Logic")
        lbl_logic_icon.setStyleSheet("font-size: 13px; font-weight: 800; color: #c084fc;")
        pill_logic = QLabel("Alt+L")
        pill_logic.setStyleSheet("background: #7e22ce; color: #ffffff; font-size: 9.5px; font-weight: 800; padding: 2px 6px; border-radius: 4px;")
        c_logic_top.addWidget(lbl_logic_icon)
        c_logic_top.addStretch()
        c_logic_top.addWidget(pill_logic)
        c_logic_layout.addLayout(c_logic_top)

        lbl_logic_sub = QLabel("State Machines • Race Conditions")
        lbl_logic_sub.setStyleSheet("font-size: 10px; font-weight: 700; color: #d8b4fe;")
        c_logic_layout.addWidget(lbl_logic_sub)

        lbl_logic_desc = QLabel("Parameter tampering, pricing flaws, MFA step-skipping & invariants.")
        lbl_logic_desc.setStyleSheet("font-size: 10.5px; color: #94a3b8; line-height: 1.2;")
        lbl_logic_desc.setWordWrap(True)
        c_logic_layout.addWidget(lbl_logic_desc)
        c_logic_layout.addStretch()

        self.btn_hp_open_logic = QPushButton("Open Workbench ➔")
        self.btn_hp_open_logic.setStyleSheet("background-color: #7e22ce; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 10px; font-size: 11px;")
        self.btn_hp_open_logic.clicked.connect(lambda: self._switch_page(15))
        c_logic_layout.addWidget(self.btn_hp_open_logic)

        cards_layout.addWidget(card_logic, stretch=1)

        # Card 3: Responsive Viewports
        card_view = QFrame()
        card_view.setStyleSheet("""
            QFrame {
                background-color: #0d1720;
                border: 1px solid #1a2c3d;
                border-radius: 10px;
            }
            QFrame:hover {
                background-color: #122130;
                border-color: #0ea5e9;
            }
        """)
        c_view_layout = QVBoxLayout(card_view)
        c_view_layout.setContentsMargins(12, 10, 12, 10)
        c_view_layout.setSpacing(6)

        c_view_top = QHBoxLayout()
        lbl_view_icon = QLabel("📱 Viewports & Devices")
        lbl_view_icon.setStyleSheet("font-size: 13px; font-weight: 800; color: #38bdf8;")
        pill_view = QLabel("Alt+V")
        pill_view.setStyleSheet("background: #0369a1; color: #ffffff; font-size: 9.5px; font-weight: 800; padding: 2px 6px; border-radius: 4px;")
        c_view_top.addWidget(lbl_view_icon)
        c_view_top.addStretch()
        c_view_top.addWidget(pill_view)
        c_view_layout.addLayout(c_view_top)

        lbl_view_sub = QLabel("Mobile • Tablet • 4K Desktop")
        lbl_view_sub.setStyleSheet("font-size: 10px; font-weight: 700; color: #7dd3fc;")
        c_view_layout.addWidget(lbl_view_sub)

        lbl_view_desc = QLabel("Layout reflow, CSS clipping, text wrapping & multi-device emulation.")
        lbl_view_desc.setStyleSheet("font-size: 10.5px; color: #94a3b8; line-height: 1.2;")
        lbl_view_desc.setWordWrap(True)
        c_view_layout.addWidget(lbl_view_desc)
        c_view_layout.addStretch()

        self.btn_hp_open_compat = QPushButton("Open Workbench ➔")
        self.btn_hp_open_compat.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 10px; font-size: 11px;")
        self.btn_hp_open_compat.clicked.connect(lambda: self._switch_page(13))
        c_view_layout.addWidget(self.btn_hp_open_compat)

        cards_layout.addWidget(card_view, stretch=1)

        # Card 4: QA Automation & CI/CD
        card_qa = QFrame()
        card_qa.setStyleSheet("""
            QFrame {
                background-color: #0d1e18;
                border: 1px solid #1a3b2b;
                border-radius: 10px;
            }
            QFrame:hover {
                background-color: #122920;
                border-color: #10b981;
            }
        """)
        c_qa_layout = QVBoxLayout(card_qa)
        c_qa_layout.setContentsMargins(12, 10, 12, 10)
        c_qa_layout.setSpacing(6)

        c_qa_top = QHBoxLayout()
        lbl_qa_icon = QLabel("🧪 QA Automation")
        lbl_qa_icon.setStyleSheet("font-size: 13px; font-weight: 800; color: #34d399;")
        pill_qa = QLabel("Alt+Q")
        pill_qa.setStyleSheet("background: #047857; color: #ffffff; font-size: 9.5px; font-weight: 800; padding: 2px 6px; border-radius: 4px;")
        c_qa_top.addWidget(lbl_qa_icon)
        c_qa_top.addStretch()
        c_qa_top.addWidget(pill_qa)
        c_qa_layout.addLayout(c_qa_top)

        lbl_qa_sub = QLabel("Playwright • Pytest • CI/CD")
        lbl_qa_sub.setStyleSheet("font-size: 10px; font-weight: 700; color: #a7f3d0;")
        c_qa_layout.addWidget(lbl_qa_sub)

        lbl_qa_desc = QLabel("Automated end-to-end scripts, regression suites & CI quality gates.")
        lbl_qa_desc.setStyleSheet("font-size: 10.5px; color: #94a3b8; line-height: 1.2;")
        lbl_qa_desc.setWordWrap(True)
        c_qa_layout.addWidget(lbl_qa_desc)
        c_qa_layout.addStretch()

        self.btn_hp_open_qa = QPushButton("Open Workbench ➔")
        self.btn_hp_open_qa.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 10px; font-size: 11px;")
        self.btn_hp_open_qa.clicked.connect(lambda: self._switch_page(8))
        c_qa_layout.addWidget(self.btn_hp_open_qa)

        cards_layout.addWidget(card_qa, stretch=1)

        sc_box_layout.addLayout(cards_layout)

        # Quick Action Utilities Bar
        utils_bar = QHBoxLayout()
        utils_bar.setSpacing(8)

        lbl_util = QLabel("⚡ Enterprise Utilities:")
        lbl_util.setStyleSheet("font-size: 11px; font-weight: 700; color: #8b93a4; text-transform: uppercase;")
        utils_bar.addWidget(lbl_util)

        self.btn_hp_autopatch = QPushButton("✨ Auto-Patcher Studio")
        self.btn_hp_autopatch.setStyleSheet("background-color: #0b1a13; color: #00ff9d; border: 1px solid #164e32; border-radius: 6px; padding: 5px 12px; font-size: 11.5px; font-weight: 700;")
        self.btn_hp_autopatch.clicked.connect(self._open_autopatch_workbench)
        utils_bar.addWidget(self.btn_hp_autopatch)

        self.btn_hp_poc = QPushButton("▶ Live PoC Sandbox")
        self.btn_hp_poc.setStyleSheet("background-color: #1a0f14; color: #ff2a44; border: 1px solid #4a1520; border-radius: 6px; padding: 5px 12px; font-size: 11.5px; font-weight: 700;")
        self.btn_hp_poc.clicked.connect(self._open_poc_sandbox)
        utils_bar.addWidget(self.btn_hp_poc)

        self.btn_hp_sarif = QPushButton("🛡️ Export SARIF 2.1.0")
        self.btn_hp_sarif.setStyleSheet("background-color: #0c1524; color: #38bdf8; border: 1px solid #1e3a5f; border-radius: 6px; padding: 5px 12px; font-size: 11.5px; font-weight: 700;")
        self.btn_hp_sarif.clicked.connect(self._export_sarif)
        utils_bar.addWidget(self.btn_hp_sarif)

        self.btn_hp_webhook = QPushButton("🔔 Webhook Alerts")
        self.btn_hp_webhook.setStyleSheet("background-color: #160f24; color: #c084fc; border: 1px solid #3b1d60; border-radius: 6px; padding: 5px 12px; font-size: 11.5px; font-weight: 700;")
        self.btn_hp_webhook.clicked.connect(self._dispatch_webhook_alert)
        utils_bar.addWidget(self.btn_hp_webhook)

        utils_bar.addStretch()
        sc_box_layout.addLayout(utils_bar)

        layout.addWidget(shortcuts_box)
        layout.addStretch()

        scroll.setWidget(container)
        page_layout = QVBoxLayout(self.page_new_scan)
        page_layout.setContentsMargins(0, 0, 0, 0)
        page_layout.addWidget(scroll)

    def _select_target_type(self, ttype: TargetType):
        self._selected_target_type = ttype
        self.card_apk.setSelected(ttype == TargetType.APK)
        self.card_exe.setSelected(ttype == TargetType.EXE)
        self.card_web.setSelected(ttype == TargetType.WEB)

        if ttype == TargetType.WEB:
            self.target_icon_btn.setText("🌐")
            self.target_path_edit.setPlaceholderText("Enter target domain or URL (e.g., https://example.com)")
            self.btn_browse.hide()
        elif ttype == TargetType.APK:
            self.target_icon_btn.setText("🤖")
            self.target_path_edit.setPlaceholderText("Select Android package (.apk file)...")
            self.btn_browse.show()
        else:
            self.target_icon_btn.setText("🪟")
            self.target_path_edit.setPlaceholderText("Select Windows executable (.exe or .dll file)...")
            self.btn_browse.show()

    def _browse_file(self):
        filter_str = "Supported Targets (*.apk *.exe *.dll);;Android APK (*.apk);;Windows Executable (*.exe *.dll);;All Files (*.*)"
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Target Binary or Package", "", filter_str
        )
        if file_path:
            self.target_path_edit.setText(file_path)
            if file_path.lower().endswith(".apk"):
                self._select_target_type(TargetType.APK)
            elif file_path.lower().endswith(".exe") or file_path.lower().endswith(".dll"):
                self._select_target_type(TargetType.EXE)

    # =========================================================================
    # PAGE 1: LIVE SCAN PROGRESS
    # =========================================================================
    def _setup_progress_page(self):
        layout = QVBoxLayout(self.page_progress)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(14)

        header_box = QFrame()
        header_box.setObjectName("CardFrame")
        h_layout = QVBoxLayout(header_box)
        h_layout.setContentsMargins(16, 14, 16, 14)
        h_layout.setSpacing(8)

        self.scan_headline = QLabel("Awaiting Target Selection...")
        self.scan_headline.setStyleSheet("font-size: 16px; font-weight: 800; color: #ff2a44;")
        h_layout.addWidget(self.scan_headline)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        h_layout.addWidget(self.progress_bar)
        layout.addWidget(header_box)

        # Terminal Log Console
        self.log_console = QTextEdit()
        self.log_console.setObjectName("LogConsole")
        self.log_console.setReadOnly(True)
        layout.addWidget(self.log_console, stretch=1)

        # Bottom Buttons
        btn_row = QHBoxLayout()
        self.cancel_btn = QPushButton("Cancel Scan Execution")
        self.cancel_btn.setStyleSheet("background-color: #231217; color: #ff2a44; border: 1px solid #ff2a44; font-weight: 700; border-radius: 8px; padding: 10px 20px;")
        self.cancel_btn.clicked.connect(self._cancel_scan)
        btn_row.addWidget(self.cancel_btn)
        btn_row.addStretch()
        layout.addLayout(btn_row)

    # =========================================================================
    # PAGE 2: EXECUTIVE THREAT ANALYSIS
    # =========================================================================
    def _setup_threat_page(self):
        layout = QVBoxLayout(self.page_threat)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(14)

        t_title = QLabel("EXECUTIVE ATTACK SURFACE & THREAT ANALYSIS")
        t_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #ff2a44; letter-spacing: 0.5px;")
        layout.addWidget(t_title)

        self.threat_narrative = QTextEdit()
        self.threat_narrative.setReadOnly(True)
        self.threat_narrative.setMaximumHeight(80)
        self.threat_narrative.setStyleSheet("background-color: #12151d; border: 1px solid #ff2a44; border-radius: 8px; padding: 10px; font-size: 12.5px; color: #ffffff;")
        layout.addWidget(self.threat_narrative)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")
        container = QWidget()
        self.attacks_layout = QVBoxLayout(container)
        self.attacks_layout.setContentsMargins(0, 0, 0, 0)
        self.attacks_layout.setSpacing(10)

        self.attacks_placeholder = QLabel("Run a security scan to populate executive threat scenarios.")
        self.attacks_placeholder.setStyleSheet("font-size: 12.5px; color: #7b8497; font-style: italic;")
        self.attacks_layout.addWidget(self.attacks_placeholder)
        self.attacks_layout.addStretch()

        scroll.setWidget(container)
        layout.addWidget(scroll, stretch=1)

    # =========================================================================
    # PAGE 3: TECHNICAL FINDINGS & REMEDIATION
    # =========================================================================
    def _setup_findings_page(self):
        layout = QVBoxLayout(self.page_findings)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # 6 KPI cards
        metrics_bar = QHBoxLayout()
        metrics_bar.setSpacing(10)

        self.card_grade = self._create_metric_card("GRADE", "--", "#00d4ff")
        self.card_score = self._create_metric_card("SCORE", "100.0", "#ff2a44")
        self.card_crit = self._create_metric_card("CRITICAL", "0", "#ff2a44")
        self.card_high = self._create_metric_card("HIGH", "0", "#ff6b22")
        self.card_med = self._create_metric_card("MEDIUM", "0", "#ffb800")
        self.card_low = self._create_metric_card("LOW", "0", "#00d4ff")
        self.card_pass = self._create_metric_card("PASSED", "0", "#00ff9d")

        metrics_bar.addWidget(self.card_grade)
        metrics_bar.addWidget(self.card_score)
        metrics_bar.addWidget(self.card_crit)
        metrics_bar.addWidget(self.card_high)
        metrics_bar.addWidget(self.card_med)
        metrics_bar.addWidget(self.card_low)
        metrics_bar.addWidget(self.card_pass)
        layout.addLayout(metrics_bar)

        # Splitter: Left Table, Right Remediation Inspector
        splitter = QSplitter(Qt.Horizontal)

        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        filter_row = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Filter findings by keyword...")
        self.search_edit.textChanged.connect(self._apply_filter)

        self.filter_combo = QComboBox()
        self.filter_combo.addItem("All Severities")
        self.filter_combo.addItem("Critical & High")
        self.filter_combo.addItem("Medium & Low")
        self.filter_combo.addItem("Passed Checks")
        self.filter_combo.currentIndexChanged.connect(self._apply_filter)

        filter_row.addWidget(self.search_edit)
        filter_row.addWidget(self.filter_combo)
        left_layout.addLayout(filter_row)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Check ID", "Severity", "Finding Title", "Category", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setSelectionMode(QTableWidget.SingleSelection)
        self.table.itemSelectionChanged.connect(self._on_finding_selected)
        left_layout.addWidget(self.table)
        splitter.addWidget(left_widget)

        # Right Inspector Panel
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        right_widget = QWidget()
        self.right_layout = QVBoxLayout(right_widget)
        self.right_layout.setContentsMargins(14, 12, 14, 12)
        self.right_layout.setSpacing(10)

        self.inspector_title = QLabel("Select a Finding to Inspect Remediation")
        self.inspector_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #ff2a44;")
        self.inspector_title.setWordWrap(True)
        self.right_layout.addWidget(self.inspector_title)

        self.inspector_meta = QLabel("")
        self.inspector_meta.setStyleSheet("font-size: 11.5px; color: #7b8497;")
        self.right_layout.addWidget(self.inspector_meta)

        self.inspector_evidence = QTextEdit()
        self.inspector_evidence.setObjectName("LogConsole")
        self.inspector_evidence.setReadOnly(True)
        self.inspector_evidence.setMaximumHeight(90)
        self.right_layout.addWidget(QLabel("EVIDENCE:"))
        self.right_layout.addWidget(self.inspector_evidence)

        self.inspector_impact = QLabel("")
        self.inspector_impact.setWordWrap(True)
        self.inspector_impact.setStyleSheet("font-size: 12.5px; color: #d7e0f0;")
        self.right_layout.addWidget(QLabel("POTENTIAL IMPACT:"))
        self.right_layout.addWidget(self.inspector_impact)

        self.inspector_remediation = QLabel("")
        self.inspector_remediation.setWordWrap(True)
        self.inspector_remediation.setStyleSheet("font-size: 12.5px; color: #00ff9d; font-weight: 600;")
        self.right_layout.addWidget(QLabel("REMEDIATION STEPS:"))
        self.right_layout.addWidget(self.inspector_remediation)

        self.inspector_code = QTextEdit()
        self.inspector_code.setObjectName("LogConsole")
        self.inspector_code.setReadOnly(True)
        self.inspector_code.setMaximumHeight(110)
        self.right_layout.addWidget(QLabel("SECURE CODE IMPLEMENTATION:"))
        self.right_layout.addWidget(self.inspector_code)

        self.inspector_verif = QLabel("")
        self.inspector_verif.setWordWrap(True)
        self.right_layout.addWidget(QLabel("VERIFICATION TEST:"))
        self.right_layout.addWidget(self.inspector_verif)

        # Interactive Remediation Action Bar
        action_btn_box = QHBoxLayout()
        action_btn_box.setSpacing(8)

        self.btn_finding_autopatch = QPushButton("✨ Auto-Patcher (.patch)")
        self.btn_finding_autopatch.setStyleSheet("""
            QPushButton {
                background-color: #00ff9d;
                color: #0b0f19;
                font-weight: 800;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 11.5px;
            }
            QPushButton:hover {
                background-color: #34d399;
            }
        """)
        self.btn_finding_autopatch.clicked.connect(self._show_patch_modal_for_finding)
        action_btn_box.addWidget(self.btn_finding_autopatch)

        self.btn_finding_poc = QPushButton("▶ Live PoC Sandbox")
        self.btn_finding_poc.setStyleSheet("""
            QPushButton {
                background-color: #ff2a44;
                color: #ffffff;
                font-weight: 800;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 11.5px;
            }
            QPushButton:hover {
                background-color: #ff475e;
            }
        """)
        self.btn_finding_poc.clicked.connect(self._run_live_poc_for_finding)
        action_btn_box.addWidget(self.btn_finding_poc)

        self.right_layout.addLayout(action_btn_box)
        self.right_layout.addStretch()

        right_scroll.setWidget(right_widget)
        splitter.addWidget(right_scroll)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

        # Export row
        export_row = QHBoxLayout()
        export_row.addStretch()
        self.btn_export_html = QPushButton("📄 Export HTML Report")
        self.btn_export_html.clicked.connect(self._export_html)
        self.btn_export_json = QPushButton("⚙️ Export JSON Audit Data")
        self.btn_export_json.clicked.connect(self._export_json)
        self.btn_export_sarif = QPushButton("🛡️ Export OASIS SARIF 2.1.0")
        self.btn_export_sarif.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 7px; padding: 7px 14px; font-size: 12px; font-weight: 700;")
        self.btn_export_sarif.clicked.connect(self._export_sarif)
        self.btn_dispatch_webhook = QPushButton("🔔 Dispatch Webhook Alert")
        self.btn_dispatch_webhook.setStyleSheet("background-color: #1a162b; color: #c084fc; border: 1px solid #7c3aed; border-radius: 7px; padding: 7px 14px; font-size: 12px; font-weight: 700;")
        self.btn_dispatch_webhook.clicked.connect(self._dispatch_webhook_alert)

        export_row.addWidget(self.btn_export_html)
        export_row.addWidget(self.btn_export_json)
        export_row.addWidget(self.btn_export_sarif)
        export_row.addWidget(self.btn_dispatch_webhook)
        layout.addLayout(export_row)

    def _create_metric_card(self, label: str, value: str, color: str) -> QFrame:
        card = QFrame()
        card.setObjectName("CardFrame")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setAlignment(Qt.AlignCenter)

        val_lbl = QLabel(value)
        val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {color};")
        val_lbl.setAlignment(Qt.AlignCenter)

        sub_lbl = QLabel(label)
        sub_lbl.setStyleSheet("font-size: 9px; color: #7b8497; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;")
        sub_lbl.setAlignment(Qt.AlignCenter)

        layout.addWidget(val_lbl)
        layout.addWidget(sub_lbl)
        card.val_lbl = val_lbl
        card.sub_lbl = sub_lbl
        return card

    # =========================================================================
    # PAGE 4: BUG FINDER & DEFECTS
    # =========================================================================
    def _setup_bugs_page(self):
        layout = QVBoxLayout(self.page_bugs)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Title
        b_hdr = QHBoxLayout()
        t_lbl = QLabel("🐞 DEDICATED BUG FINDER & SOFTWARE DEFECTS")
        t_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #ff2a44;")
        b_hdr.addWidget(t_lbl)
        b_hdr.addStretch()
        layout.addLayout(b_hdr)

        # 6 KPI cards
        b_kpis = QHBoxLayout()
        b_kpis.setSpacing(10)
        self.card_bug_total = self._create_metric_card("TOTAL", "0", "#ff2a44")
        self.card_bug_leaks = self._create_metric_card("LEAKS", "0", "#ff6b22")
        self.card_bug_links = self._create_metric_card("LINKS", "0", "#ffb800")
        self.card_bug_forms = self._create_metric_card("FORMS", "0", "#00d4ff")
        self.card_bug_crashes = self._create_metric_card("CRASHES", "0", "#ff2a44")
        self.card_bug_banned = self._create_metric_card("BANNED APIS", "0", "#a855f7")

        b_kpis.addWidget(self.card_bug_total)
        b_kpis.addWidget(self.card_bug_leaks)
        b_kpis.addWidget(self.card_bug_links)
        b_kpis.addWidget(self.card_bug_forms)
        b_kpis.addWidget(self.card_bug_crashes)
        b_kpis.addWidget(self.card_bug_banned)
        layout.addLayout(b_kpis)

        # Filter bar
        fltr_bar = QHBoxLayout()
        self.bugs_search_edit = QLineEdit()
        self.bugs_search_edit.setPlaceholderText("Search defects by component or title...")
        self.bugs_search_edit.textChanged.connect(self._filter_bugs)

        self.bugs_cat_combo = QComboBox()
        self.bugs_cat_combo.addItem("All Defect Categories")
        self.bugs_cat_combo.addItem("Memory & Handle Leaks")
        self.bugs_cat_combo.addItem("Navigation & Broken Links")
        self.bugs_cat_combo.addItem("Form & Input Boundaries")
        self.bugs_cat_combo.addItem("Crash & Exception Hazards")
        self.bugs_cat_combo.addItem("Manifest & GUI Defects")
        self.bugs_cat_combo.currentIndexChanged.connect(self._filter_bugs)

        fltr_bar.addWidget(self.bugs_search_edit)
        fltr_bar.addWidget(self.bugs_cat_combo)
        layout.addLayout(fltr_bar)

        # Splitter: Table Left, Patch Inspector Right
        splitter = QSplitter(Qt.Horizontal)

        self.bugs_table = QTableWidget()
        self.bugs_table.setColumnCount(5)
        self.bugs_table.setHorizontalHeaderLabels(["ID", "Severity", "Defect Title", "Component", "Status"])
        self.bugs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.bugs_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.bugs_table.setSelectionMode(QTableWidget.SingleSelection)
        self.bugs_table.itemSelectionChanged.connect(self._on_bug_selected)
        splitter.addWidget(self.bugs_table)

        # Patch Inspector
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        r_widget = QWidget()
        r_layout = QVBoxLayout(r_widget)
        r_layout.setContentsMargins(14, 12, 14, 12)
        r_layout.setSpacing(10)

        self.bug_insp_title = QLabel("Select a Defect to View Remediation Patch")
        self.bug_insp_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #ff2a44;")
        self.bug_insp_title.setWordWrap(True)
        r_layout.addWidget(self.bug_insp_title)

        self.bug_insp_component = QLabel("")
        self.bug_insp_component.setStyleSheet("font-size: 11.5px; color: #7b8497;")
        r_layout.addWidget(self.bug_insp_component)

        self.bug_insp_evidence = QTextEdit()
        self.bug_insp_evidence.setObjectName("LogConsole")
        self.bug_insp_evidence.setReadOnly(True)
        self.bug_insp_evidence.setMaximumHeight(85)
        r_layout.addWidget(QLabel("ROOT CAUSE & EVIDENCE:"))
        r_layout.addWidget(self.bug_insp_evidence)

        self.bug_insp_patch = QTextEdit()
        self.bug_insp_patch.setObjectName("LogConsole")
        self.bug_insp_patch.setReadOnly(True)
        self.bug_insp_patch.setMaximumHeight(120)
        r_layout.addWidget(QLabel("ACTIONABLE REMEDIATION PATCH:"))
        r_layout.addWidget(self.bug_insp_patch)

        # Autonomous Patch & Live PoC Action Bar
        bug_action_box = QHBoxLayout()
        bug_action_box.setSpacing(8)

        self.btn_bug_autopatch = QPushButton("✨ Apply Autonomous Patch (.patch)")
        self.btn_bug_autopatch.setStyleSheet("""
            QPushButton {
                background-color: #00ff9d;
                color: #0b0f19;
                font-weight: 800;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 11.5px;
            }
            QPushButton:hover {
                background-color: #34d399;
            }
        """)
        self.btn_bug_autopatch.clicked.connect(self._show_patch_modal_for_bug)
        bug_action_box.addWidget(self.btn_bug_autopatch)

        self.btn_bug_poc = QPushButton("▶ Run Live Verification PoC")
        self.btn_bug_poc.setStyleSheet("""
            QPushButton {
                background-color: #ff2a44;
                color: #ffffff;
                font-weight: 800;
                border: none;
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 11.5px;
            }
            QPushButton:hover {
                background-color: #ff475e;
            }
        """)
        self.btn_bug_poc.clicked.connect(self._run_live_poc_for_bug)
        bug_action_box.addWidget(self.btn_bug_poc)

        r_layout.addLayout(bug_action_box)
        r_layout.addStretch()

        right_scroll.setWidget(r_widget)
        splitter.addWidget(right_scroll)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 5: WEBSITE HISTORY & ADMIN INTEL
    # =========================================================================
    def _setup_web_history_page(self):
        layout = QVBoxLayout(self.page_web_history)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        wh_header_vbox = QVBoxLayout()
        wh_header_vbox.setSpacing(4)
        wh_header_vbox.setContentsMargins(0, 0, 0, 0)

        wh_hdr = QHBoxLayout()
        t_lbl = QLabel("🌐 WEBSITE HISTORY, RDAP CHRONOLOGY & ADMIN INTELLIGENCE")
        t_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #00ff9d;")
        wh_hdr.addWidget(t_lbl)
        wh_hdr.addStretch()
        wh_header_vbox.addLayout(wh_hdr)

        self.hist_target_lbl = QLabel("")
        self.hist_target_lbl.setStyleSheet("font-size: 11.5px; color: #7b8497;")
        self.hist_target_lbl.setWordWrap(True)
        wh_header_vbox.addWidget(self.hist_target_lbl)

        layout.addLayout(wh_header_vbox)

        # 6 KPI cards
        wh_kpis = QHBoxLayout()
        wh_kpis.setSpacing(10)
        self.card_hist_age = self._create_metric_card("AGE", "--", "#00d4ff")
        self.card_hist_reg = self._create_metric_card("REGISTERED", "--", "#00ff9d")
        self.card_hist_exp = self._create_metric_card("EXPIRY", "--", "#ffb800")
        self.card_hist_type = self._create_metric_card("CATEGORY", "--", "#ff2a44")
        self.card_hist_size = self._create_metric_card("EST. SIZE", "--", "#00d4ff")
        self.card_hist_admin = self._create_metric_card("ADMIN SCORE", "--", "#00ff9d")

        wh_kpis.addWidget(self.card_hist_age)
        wh_kpis.addWidget(self.card_hist_reg)
        wh_kpis.addWidget(self.card_hist_exp)
        wh_kpis.addWidget(self.card_hist_type)
        wh_kpis.addWidget(self.card_hist_size)
        wh_kpis.addWidget(self.card_hist_admin)
        layout.addLayout(wh_kpis)

        splitter = QSplitter(Qt.Horizontal)

        # Left: Admin Behavior & Past Incidents
        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        l_widget = QWidget()
        l_layout = QVBoxLayout(l_widget)
        l_layout.setContentsMargins(10, 10, 10, 10)
        l_layout.setSpacing(12)

        admin_card = QFrame()
        admin_card.setObjectName("CardFrame")
        ac_layout = QVBoxLayout(admin_card)
        ac_title = QLabel("👨‍💼 Administrator Behavior & Technical Maturity Profile")
        ac_title.setStyleSheet("font-size: 13.5px; font-weight: 700; color: #ff2a44;")
        self.hist_admin_tier_lbl = QLabel("Awaiting Web Audit")
        self.hist_admin_tier_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #00ff9d;")
        self.hist_admin_summary_lbl = QLabel("")
        self.hist_admin_summary_lbl.setWordWrap(True)
        self.hist_admin_summary_lbl.setStyleSheet("font-size: 12px; color: #cbd5e1;")
        ac_layout.addWidget(ac_title)
        ac_layout.addWidget(self.hist_admin_tier_lbl)
        ac_layout.addWidget(self.hist_admin_summary_lbl)

        ac_layout.addWidget(QLabel("OBSERVED DEFENSIVE STRENGTHS:"))
        self.hist_admin_strengths_txt = QTextEdit()
        self.hist_admin_strengths_txt.setReadOnly(True)
        self.hist_admin_strengths_txt.setMaximumHeight(65)
        self.hist_admin_strengths_txt.setStyleSheet("background: #0b0f16; color: #00ff9d; font-size: 11.5px;")
        ac_layout.addWidget(self.hist_admin_strengths_txt)

        ac_layout.addWidget(QLabel("ADMINISTRATIVE BLIND SPOTS:"))
        self.hist_admin_blindspots_txt = QTextEdit()
        self.hist_admin_blindspots_txt.setReadOnly(True)
        self.hist_admin_blindspots_txt.setMaximumHeight(65)
        self.hist_admin_blindspots_txt.setStyleSheet("background: #0b0f16; color: #ffb800; font-size: 11.5px;")
        ac_layout.addWidget(self.hist_admin_blindspots_txt)
        l_layout.addWidget(admin_card)

        # Past Incidents Card
        sec_card = QFrame()
        sec_card.setObjectName("CardFrame")
        sc_layout = QVBoxLayout(sec_card)
        sc_title = QLabel("🛡️ Historical Security & Past Incident Forensics")
        sc_title.setStyleSheet("font-size: 13.5px; font-weight: 700; color: #00ff9d;")
        self.hist_sec_risk_lbl = QLabel("Defacement Risk: Low | Outages: Stable")
        self.hist_sec_risk_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #f0f4fc;")
        self.hist_sec_notes_txt = QTextEdit()
        self.hist_sec_notes_txt.setReadOnly(True)
        self.hist_sec_notes_txt.setMaximumHeight(70)
        self.hist_sec_notes_txt.setStyleSheet("background: #0b0f16; color: #cbd5e1; font-size: 11.5px;")
        sc_layout.addWidget(sc_title)
        sc_layout.addWidget(self.hist_sec_risk_lbl)
        sc_layout.addWidget(self.hist_sec_notes_txt)
        l_layout.addWidget(sec_card)
        l_layout.addStretch()

        left_scroll.setWidget(l_widget)
        splitter.addWidget(left_scroll)

        # Right: Evolutionary Timeline
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        r_widget = QWidget()
        self.hist_timeline_layout = QVBoxLayout(r_widget)
        self.hist_timeline_layout.setContentsMargins(12, 10, 12, 10)
        self.hist_timeline_layout.setSpacing(8)

        t_head = QLabel("📅 Year-by-Year Evolutionary Upgrades Timeline")
        t_head.setStyleSheet("font-size: 14px; font-weight: 700; color: #00d4ff;")
        self.hist_timeline_layout.addWidget(t_head)

        self.hist_placeholder_lbl = QLabel("Execute or load a website audit to view the evolutionary timeline.")
        self.hist_placeholder_lbl.setStyleSheet("font-size: 12px; color: #7b8497; font-style: italic;")
        self.hist_timeline_layout.addWidget(self.hist_placeholder_lbl)
        self.hist_timeline_layout.addStretch()

        right_scroll.setWidget(r_widget)
        splitter.addWidget(right_scroll)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 6: TEST A HACK (ATTACK RESILIENCE SIMULATOR)
    # =========================================================================
    def _setup_attacks_page(self):
        layout = QVBoxLayout(self.page_attacks)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header Title
        title_box = QHBoxLayout()
        title_lbl = QLabel("⚔️ TEST A HACK: THEORETICAL ATTACK RESILIENCE SIMULATOR")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #ff2a44;")
        title_box.addWidget(title_lbl)
        title_box.addStretch()
        self.btn_export_atk_html = QPushButton("📄 Export Resilience Report (HTML)")
        self.btn_export_atk_html.clicked.connect(self._export_html)
        title_box.addWidget(self.btn_export_atk_html)
        layout.addLayout(title_box)

        # 6 KPI Stat Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)
        self.card_atk_survival = self._create_metric_card("SURVIVAL", "-- %", "#00ff9d")
        self.card_atk_verdict = self._create_metric_card("RESILIENCE", "Awaiting Audit", "#f0f4fc")
        self.card_atk_total = self._create_metric_card("SCENARIOS", "0", "#00d4ff")
        self.card_atk_hardened = self._create_metric_card("HARDENED", "0", "#00ff9d")
        self.card_atk_moderate = self._create_metric_card("MODERATE", "0", "#ffb800")
        self.card_atk_critical = self._create_metric_card("CRITICAL", "0", "#ff2a44")

        stats_layout.addWidget(self.card_atk_survival)
        stats_layout.addWidget(self.card_atk_verdict)
        stats_layout.addWidget(self.card_atk_total)
        stats_layout.addWidget(self.card_atk_hardened)
        stats_layout.addWidget(self.card_atk_moderate)
        stats_layout.addWidget(self.card_atk_critical)
        layout.addLayout(stats_layout)

        # Filter buttons bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(6)
        self.btn_fltr_atk_all = QPushButton("All Scenarios")
        self.btn_fltr_atk_web = QPushButton("Web (SQLi, DDoS, XSS, BOLA)")
        self.btn_fltr_atk_win = QPushButton("Windows OS (BOF, DLL)")
        self.btn_fltr_atk_infra = QPushButton("Infra & AD (PtH, Ransomware, SSRF)")
        self.btn_fltr_atk_crit = QPushButton("Critical Exposure (<50% Survival)")

        for btn in (self.btn_fltr_atk_all, self.btn_fltr_atk_web, self.btn_fltr_atk_win, self.btn_fltr_atk_infra, self.btn_fltr_atk_crit):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 12px; font-size: 11.5px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_atk_all.clicked.connect(lambda: self._filter_attacks("all"))
        self.btn_fltr_atk_web.clicked.connect(lambda: self._filter_attacks("web"))
        self.btn_fltr_atk_win.clicked.connect(lambda: self._filter_attacks("win"))
        self.btn_fltr_atk_infra.clicked.connect(lambda: self._filter_attacks("infra"))
        self.btn_fltr_atk_crit.clicked.connect(lambda: self._filter_attacks("crit"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        splitter = QSplitter(Qt.Horizontal)
        self.atk_table = QTableWidget()
        self.atk_table.setColumnCount(5)
        self.atk_table.setHorizontalHeaderLabels(["ID", "Attack Scenario", "Category", "Survival %", "Verdict"])
        self.atk_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.atk_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.atk_table.setSelectionMode(QTableWidget.SingleSelection)
        self.atk_table.itemSelectionChanged.connect(self._on_attack_selected)
        splitter.addWidget(self.atk_table)

        # Right Inspector
        right_scroll = QScrollArea()
        right_scroll.setWidgetResizable(True)
        r_widget = QWidget()
        r_layout = QVBoxLayout(r_widget)
        r_layout.setContentsMargins(14, 12, 14, 12)
        r_layout.setSpacing(10)

        self.atk_insp_title = QLabel("Select an attack scenario from the table to inspect survival dynamics.")
        self.atk_insp_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #ff2a44;")
        self.atk_insp_title.setWordWrap(True)
        r_layout.addWidget(self.atk_insp_title)

        self.atk_insp_survival_bar = QLabel("Survival Probability: -- %")
        self.atk_insp_survival_bar.setStyleSheet("font-size: 13px; font-weight: 800; color: #00ff9d; background: #0c1322; padding: 7px 12px; border-radius: 6px;")
        r_layout.addWidget(self.atk_insp_survival_bar)

        r_layout.addWidget(QLabel("THREAT ACTOR OBJECTIVE:"))
        self.atk_insp_objective = QTextEdit()
        self.atk_insp_objective.setReadOnly(True)
        self.atk_insp_objective.setMaximumHeight(55)
        self.atk_insp_objective.setStyleSheet("background: #0b0f16; color: #cfdaf0; font-size: 11.5px;")
        r_layout.addWidget(self.atk_insp_objective)

        r_layout.addWidget(QLabel("THEORETICAL EXPLOIT VECTOR MECHANICS:"))
        self.atk_insp_mechanics = QTextEdit()
        self.atk_insp_mechanics.setReadOnly(True)
        self.atk_insp_mechanics.setMaximumHeight(80)
        self.atk_insp_mechanics.setStyleSheet("background: #0b0f16; color: #cfdaf0; font-size: 11.5px;")
        r_layout.addWidget(self.atk_insp_mechanics)

        two_col = QHBoxLayout()
        v_col1 = QVBoxLayout()
        v_col1.addWidget(QLabel("CONFIRMED DEFENSIVE CONTROLS:"))
        self.atk_insp_defenses = QTextEdit()
        self.atk_insp_defenses.setReadOnly(True)
        self.atk_insp_defenses.setMaximumHeight(90)
        self.atk_insp_defenses.setStyleSheet("background: #080d1a; color: #00ff9d; font-size: 11px;")
        v_col1.addWidget(self.atk_insp_defenses)
        two_col.addLayout(v_col1)

        v_col2 = QVBoxLayout()
        v_col2.addWidget(QLabel("VULNERABILITIES LOWERING SURVIVAL:"))
        self.atk_insp_penalties = QTextEdit()
        self.atk_insp_penalties.setReadOnly(True)
        self.atk_insp_penalties.setMaximumHeight(90)
        self.atk_insp_penalties.setStyleSheet("background: #080d1a; color: #ff6b22; font-size: 11px;")
        v_col2.addWidget(self.atk_insp_penalties)
        two_col.addLayout(v_col2)
        r_layout.addLayout(two_col)

        r_layout.addWidget(QLabel("ACTIONABLE HARDENING (TARGET: 95%+ SURVIVAL):"))
        self.atk_insp_hardening = QTextEdit()
        self.atk_insp_hardening.setReadOnly(True)
        self.atk_insp_hardening.setMaximumHeight(100)
        self.atk_insp_hardening.setStyleSheet("background: #0b0f16; color: #00d4ff; font-size: 11.5px;")
        r_layout.addWidget(self.atk_insp_hardening)
        r_layout.addStretch()

        right_scroll.setWidget(r_widget)
        splitter.addWidget(right_scroll)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 7: SCAN HISTORY ARCHIVE
    # =========================================================================
    def _setup_history_page(self):
        layout = QVBoxLayout(self.page_history)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        h_title = QLabel("RECORDED SECURITY AUDIT ARCHIVE")
        h_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #00d4ff;")
        layout.addWidget(h_title)

        self.hist_table = QTableWidget()
        self.hist_table.setColumnCount(8)
        self.hist_table.setHorizontalHeaderLabels([
            "Target Name", "Type", "Level", "Grade", "Score", "Critical/High", "Timestamp", "Duration"
        ])
        self.hist_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.hist_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.hist_table.setSelectionMode(QTableWidget.SingleSelection)
        layout.addWidget(self.hist_table)

        btn_row = QHBoxLayout()
        self.btn_load_hist = QPushButton("Load Selected Scan Result")
        self.btn_load_hist.setStyleSheet("background-color: #ff2a44; color: #ffffff; font-weight: 700; border: none; border-radius: 8px; padding: 8px 18px;")
        self.btn_load_hist.clicked.connect(self._load_selected_history)

        self.btn_del_hist = QPushButton("Delete Selected Record")
        self.btn_del_hist.clicked.connect(self._delete_selected_history)

        btn_row.addWidget(self.btn_load_hist)
        btn_row.addWidget(self.btn_del_hist)
        btn_row.addStretch()
        layout.addLayout(btn_row)

    # =========================================================================
    # PAGE 8: QA AUTOMATION & POPULAR TOOLS TESTING
    # =========================================================================
    def _setup_automation_page(self):
        layout = QVBoxLayout(self.page_automation)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Modernized 2-Row Header Layout (eliminates label collision & button squashing)
        qa_header_vbox = QVBoxLayout()
        qa_header_vbox.setSpacing(4)
        qa_header_vbox.setContentsMargins(0, 0, 0, 0)

        qa_top_row = QHBoxLayout()
        qa_top_row.setSpacing(10)
        h_title = QLabel("🧪 POPULAR TOOLS TEST AUTOMATION & QA DELIVERABLES")
        h_title.setStyleSheet("font-size: 16px; font-weight: 800; color: #00ff9d;")
        qa_top_row.addWidget(h_title)
        qa_top_row.addStretch()

        # Action buttons
        self.btn_copy_qa_markdown = QPushButton("📋 Copy Client Report")
        self.btn_copy_qa_markdown.setStyleSheet("background-color: #00d4ff; color: #0b0f19; font-weight: 800; border: none; border-radius: 7px; padding: 7px 15px; font-size: 12px;")
        self.btn_copy_qa_markdown.clicked.connect(self._copy_qa_report_to_clipboard)
        qa_top_row.addWidget(self.btn_copy_qa_markdown)

        self.btn_export_qa_html = QPushButton("💾 Export Deliverable HTML")
        self.btn_export_qa_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 7px; padding: 7px 14px; font-size: 12px; font-weight: 700;")
        self.btn_export_qa_html.clicked.connect(self._export_qa_html)
        qa_top_row.addWidget(self.btn_export_qa_html)

        self.btn_rerun_qa = QPushButton("🔄 Re-run Suite")
        self.btn_rerun_qa.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 7px; padding: 7px 13px; font-size: 12px;")
        self.btn_rerun_qa.clicked.connect(self._rerun_qa_tests)
        qa_top_row.addWidget(self.btn_rerun_qa)

        qa_header_vbox.addLayout(qa_top_row)

        self.qa_target_lbl = QLabel("Target: Awaiting Scan or Test Execution | Supported: Web (Playwright/Selenium), Windows (WinAppDriver/Ranorex), Android (Appium/Espresso)")
        self.qa_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4;")
        self.qa_target_lbl.setWordWrap(True)
        qa_header_vbox.addWidget(self.qa_target_lbl)

        layout.addLayout(qa_header_vbox)

        # 6 KPI Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)
        self.card_qa_score = self._create_metric_card("QA SCORE", "--", "#00d4ff")
        self.card_qa_tests = self._create_metric_card("TOTAL TESTS", "0", "#f0f4fc")
        self.card_qa_passed = self._create_metric_card("PASSED", "0", "#00ff9d")
        self.card_qa_defects = self._create_metric_card("DEFECTS", "0", "#ff2a44")
        self.card_qa_flaky = self._create_metric_card("FLAKY RISK", "NONE", "#ffb800")
        self.card_qa_time = self._create_metric_card("EXEC TIME", "--", "#a855f7")

        stats_layout.addWidget(self.card_qa_score)
        stats_layout.addWidget(self.card_qa_tests)
        stats_layout.addWidget(self.card_qa_passed)
        stats_layout.addWidget(self.card_qa_defects)
        stats_layout.addWidget(self.card_qa_flaky)
        stats_layout.addWidget(self.card_qa_time)
        layout.addLayout(stats_layout)

        # Filter buttons bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(6)
        self.btn_fltr_qa_all = QPushButton("All Test Cases")
        self.btn_fltr_qa_pass = QPushButton("Passed Only")
        self.btn_fltr_qa_fail = QPushButton("Defects / Warnings Only")
        self.btn_fltr_qa_primary = QPushButton("Primary Tool")
        self.btn_fltr_qa_secondary = QPushButton("Secondary Tool")

        for btn in (self.btn_fltr_qa_all, self.btn_fltr_qa_pass, self.btn_fltr_qa_fail, self.btn_fltr_qa_primary, self.btn_fltr_qa_secondary):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 12px; font-size: 11.5px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_qa_all.clicked.connect(lambda: self._filter_qa_cases("all"))
        self.btn_fltr_qa_pass.clicked.connect(lambda: self._filter_qa_cases("passed"))
        self.btn_fltr_qa_fail.clicked.connect(lambda: self._filter_qa_cases("defects"))
        self.btn_fltr_qa_primary.clicked.connect(lambda: self._filter_qa_cases("primary"))
        self.btn_fltr_qa_secondary.clicked.connect(lambda: self._filter_qa_cases("secondary"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Table, Right QTabWidget
        splitter = QSplitter(Qt.Horizontal)

        # Left: QA Table
        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        self.qa_table = QTableWidget()
        self.qa_table.setColumnCount(5)
        self.qa_table.setHorizontalHeaderLabels(["Test ID", "Tool", "Test Case Name", "Status", "Duration"])
        self.qa_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.qa_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.qa_table.setSelectionMode(QTableWidget.SingleSelection)
        self.qa_table.itemSelectionChanged.connect(self._on_qa_case_selected)
        left_layout.addWidget(self.qa_table)
        splitter.addWidget(left_box)

        # Right: Tabs Widget
        self.qa_tabs = QTabWidget()
        self.qa_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 8px 16px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #00d4ff;
                border-bottom: 2px solid #00d4ff;
            }
        """)

        # Tab 1: Test Inspector
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(14, 12, 14, 12)
        insp_layout.setSpacing(10)

        self.qa_insp_title = QLabel("Select an automated test case from the table to inspect details.")
        self.qa_insp_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #00ff9d;")
        self.qa_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.qa_insp_title)

        self.qa_insp_meta = QLabel("Tool: -- | Suite: -- | Status: -- | Duration: --")
        self.qa_insp_meta.setStyleSheet("font-size: 12px; font-weight: 700; color: #00d4ff; background: #0c1322; padding: 7px 12px; border-radius: 6px; border-left: 4px solid #00d4ff;")
        insp_layout.addWidget(self.qa_insp_meta)

        insp_layout.addWidget(QLabel("ASSERTION TARGET & CRITERIA:"))
        self.qa_insp_assertion = QTextEdit()
        self.qa_insp_assertion.setReadOnly(True)
        self.qa_insp_assertion.setMaximumHeight(50)
        self.qa_insp_assertion.setStyleSheet("background: #0b0f16; color: #cfdaf0; font-size: 11.5px;")
        insp_layout.addWidget(self.qa_insp_assertion)

        two_col_res = QHBoxLayout()
        v_col_exp = QVBoxLayout()
        v_col_exp.addWidget(QLabel("EXPECTED CRITERIA:"))
        self.qa_insp_expected = QTextEdit()
        self.qa_insp_expected.setReadOnly(True)
        self.qa_insp_expected.setMaximumHeight(70)
        self.qa_insp_expected.setStyleSheet("background: #080d1a; color: #00ff9d; font-size: 11px;")
        v_col_exp.addWidget(self.qa_insp_expected)
        two_col_res.addLayout(v_col_exp)

        v_col_act = QVBoxLayout()
        v_col_act.addWidget(QLabel("ACTUAL OBSERVED TELEMETRY:"))
        self.qa_insp_actual = QTextEdit()
        self.qa_insp_actual.setReadOnly(True)
        self.qa_insp_actual.setMaximumHeight(70)
        self.qa_insp_actual.setStyleSheet("background: #080d1a; color: #ffb800; font-size: 11px;")
        v_col_act.addWidget(self.qa_insp_actual)
        two_col_res.addLayout(v_col_act)
        insp_layout.addLayout(two_col_res)

        insp_layout.addWidget(QLabel("AUTOMATION REPRODUCTION STEPS:"))
        self.qa_insp_repro = QTextEdit()
        self.qa_insp_repro.setReadOnly(True)
        self.qa_insp_repro.setMaximumHeight(70)
        self.qa_insp_repro.setStyleSheet("background: #0b0f16; color: #cfdaf0; font-size: 11.5px;")
        insp_layout.addWidget(self.qa_insp_repro)

        insp_layout.addWidget(QLabel("ACTIONABLE REMEDIATION & DEVELOPER PATCH:"))
        self.qa_insp_patch = QTextEdit()
        self.qa_insp_patch.setReadOnly(True)
        self.qa_insp_patch.setMaximumHeight(90)
        self.qa_insp_patch.setStyleSheet("background: #0b0f16; color: #38bdf8; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px;")
        insp_layout.addWidget(self.qa_insp_patch)
        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t1_layout = QVBoxLayout(tab_insp)
        t1_layout.setContentsMargins(0, 0, 0, 0)
        t1_layout.addWidget(insp_scroll)
        self.qa_tabs.addTab(tab_insp, "🔎 Test Inspector")

        # Tab 2: Ready-to-Run Automation Code
        tab_code = QWidget()
        c_layout = QVBoxLayout(tab_code)
        c_layout.setContentsMargins(14, 12, 14, 12)
        c_layout.setSpacing(8)

        c_top = QHBoxLayout()
        self.qa_script_selector = QComboBox()
        self.qa_script_selector.addItem("Primary Tool Automation Script")
        self.qa_script_selector.addItem("Secondary Tool Automation Script")
        self.qa_script_selector.currentIndexChanged.connect(self._on_qa_script_tool_changed)
        c_top.addWidget(self.qa_script_selector)
        c_top.addStretch()

        btn_copy_script = QPushButton("📋 Copy Script to Clipboard")
        btn_copy_script.setStyleSheet("background-color: #1a2333; color: #00d4ff; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-weight: 700; font-size: 11.5px;")
        btn_copy_script.clicked.connect(self._copy_qa_script_to_clipboard)
        c_top.addWidget(btn_copy_script)
        c_layout.addLayout(c_top)

        self.qa_script_txt = QTextEdit()
        self.qa_script_txt.setReadOnly(True)
        self.qa_script_txt.setStyleSheet("background: #090c13; color: #38bdf8; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        c_layout.addWidget(self.qa_script_txt)
        self.qa_tabs.addTab(tab_code, "💻 Ready-to-Run Code")

        # Tab 3: CI/CD Pipeline
        tab_cicd = QWidget()
        ci_layout = QVBoxLayout(tab_cicd)
        ci_layout.setContentsMargins(14, 12, 14, 12)
        ci_layout.setSpacing(8)

        ci_top = QHBoxLayout()
        ci_title = QLabel("Automated CI Pipeline Specification (GitHub Actions / Azure DevOps)")
        ci_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #e4e9f2;")
        ci_top.addWidget(ci_title)
        ci_top.addStretch()

        btn_copy_cicd = QPushButton("📋 Copy CI/CD YAML")
        btn_copy_cicd.setStyleSheet("background-color: #1a2333; color: #00d4ff; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-weight: 700; font-size: 11.5px;")
        btn_copy_cicd.clicked.connect(self._copy_qa_cicd_to_clipboard)
        ci_top.addWidget(btn_copy_cicd)
        ci_layout.addLayout(ci_top)

        self.qa_cicd_txt = QTextEdit()
        self.qa_cicd_txt.setReadOnly(True)
        self.qa_cicd_txt.setStyleSheet("background: #090c13; color: #a5f3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        ci_layout.addWidget(self.qa_cicd_txt)
        self.qa_tabs.addTab(tab_cicd, "⚡ CI/CD Pipeline")

        # Tab 4: Copiable Client Deliverable Report
        tab_deliv = QWidget()
        d_layout = QVBoxLayout(tab_deliv)
        d_layout.setContentsMargins(14, 12, 14, 12)
        d_layout.setSpacing(8)

        d_top = QHBoxLayout()
        d_title = QLabel("📋 Copiable Professional QA Report (Ready to Send to Client / Hiring Company)")
        d_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00ff9d;")
        d_top.addWidget(d_title)
        d_top.addStretch()

        self.btn_copy_deliverable = QPushButton("📋 Copy Full Client Report to Clipboard")
        self.btn_copy_deliverable.setStyleSheet("background-color: #00d4ff; color: #0b0f19; font-weight: 800; border: none; border-radius: 6px; padding: 7px 16px; font-size: 12px;")
        self.btn_copy_deliverable.clicked.connect(self._copy_qa_report_to_clipboard)
        d_top.addWidget(self.btn_copy_deliverable)
        d_layout.addLayout(d_top)

        self.qa_deliverable_txt = QTextEdit()
        self.qa_deliverable_txt.setReadOnly(True)
        self.qa_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        d_layout.addWidget(self.qa_deliverable_txt)
        self.qa_tabs.addTab(tab_deliv, "📋 Client Deliverable")

        splitter.addWidget(self.qa_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 9: REST & BACKEND API CONTRACT TESTING & FUZZER
    # =========================================================================
    def _setup_api_page(self):
        layout = QVBoxLayout(self.page_api)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header bar
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        h_title = QLabel("⚡ REST & Backend API Contract Testing & Fuzzer")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #00d4ff;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        self.btn_copy_api_markdown = QPushButton("📋 Copy Report")
        self.btn_copy_api_markdown.setStyleSheet("background-color: #00d4ff; color: #0b0f19; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_api_markdown.clicked.connect(self._copy_api_report_to_clipboard)
        top_row.addWidget(self.btn_copy_api_markdown)

        self.btn_export_postman = QPushButton("📬 Postman v2.1")
        self.btn_export_postman.setStyleSheet("background-color: #ff6b22; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_export_postman.clicked.connect(self._export_postman_collection)
        top_row.addWidget(self.btn_export_postman)

        self.btn_export_api_html = QPushButton("💾 Export HTML")
        self.btn_export_api_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 700;")
        self.btn_export_api_html.clicked.connect(self._export_api_html)
        top_row.addWidget(self.btn_export_api_html)

        self.btn_rerun_api = QPushButton("🔄 Re-run")
        self.btn_rerun_api.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_rerun_api.clicked.connect(self._rerun_api_tests)
        top_row.addWidget(self.btn_rerun_api)

        header_vbox.addLayout(top_row)

        self.api_target_lbl = QLabel("Target API: Awaiting Scan or Execution | Probes: OpenAPI 3.x, Swagger 2.0, REST contracts, BOLA/IDOR, Rate-Limits")
        self.api_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.api_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.api_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)
        self.card_api_score = self._create_metric_card("API SCORE", "--", "#00d4ff")
        self.card_api_endpoints = self._create_metric_card("ENDPOINTS", "0", "#f0f4fc")
        self.card_api_tests = self._create_metric_card("TESTS DISPATCHED", "0", "#00ff9d")
        self.card_api_defects = self._create_metric_card("CONTRACT DEFECTS", "0", "#ff2a44")
        self.card_api_rate_limit = self._create_metric_card("RATE LIMITING", "CHECKING", "#ffb800")
        self.card_api_latency = self._create_metric_card("AVG LATENCY", "--", "#a855f7")

        stats_layout.addWidget(self.card_api_score)
        stats_layout.addWidget(self.card_api_endpoints)
        stats_layout.addWidget(self.card_api_tests)
        stats_layout.addWidget(self.card_api_defects)
        stats_layout.addWidget(self.card_api_rate_limit)
        stats_layout.addWidget(self.card_api_latency)
        layout.addLayout(stats_layout)

        # Filter buttons bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(6)
        self.btn_fltr_api_all = QPushButton("All Test Cases")
        self.btn_fltr_api_schema = QPushButton("Contract Schema")
        self.btn_fltr_api_fuzz = QPushButton("Boundary Fuzzing")
        self.btn_fltr_api_auth = QPushButton("Auth & Access")
        self.btn_fltr_api_defects = QPushButton("Defects / Warnings Only")

        for btn in (self.btn_fltr_api_all, self.btn_fltr_api_schema, self.btn_fltr_api_fuzz, self.btn_fltr_api_auth, self.btn_fltr_api_defects):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 12px; font-size: 11.5px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_api_all.clicked.connect(lambda: self._filter_api_cases("all"))
        self.btn_fltr_api_schema.clicked.connect(lambda: self._filter_api_cases("schema"))
        self.btn_fltr_api_fuzz.clicked.connect(lambda: self._filter_api_cases("fuzz"))
        self.btn_fltr_api_auth.clicked.connect(lambda: self._filter_api_cases("auth"))
        self.btn_fltr_api_defects.clicked.connect(lambda: self._filter_api_cases("defects"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Table, Right QTabWidget
        splitter = QSplitter(Qt.Horizontal)

        # Left: API Table
        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        self.api_table = QTableWidget()
        self.api_table.setColumnCount(6)
        self.api_table.setHorizontalHeaderLabels(["Test ID", "Method", "Endpoint Path", "Category", "Status", "Latency"])
        self.api_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.api_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.api_table.setSelectionMode(QTableWidget.SingleSelection)
        self.api_table.itemSelectionChanged.connect(self._on_api_test_selected)
        left_layout.addWidget(self.api_table)
        splitter.addWidget(left_box)

        # Right: Tabs Widget
        self.api_tabs = QTabWidget()
        self.api_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 8px 16px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #00d4ff;
                border-bottom: 2px solid #00d4ff;
            }
        """)

        # Tab 1: Test & Assertion Inspector
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(14, 12, 14, 12)
        insp_layout.setSpacing(10)

        self.api_insp_title = QLabel("Select an API test case from the table to inspect telemetry.")
        self.api_insp_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #00d4ff;")
        self.api_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.api_insp_title)

        self.api_insp_meta = QLabel("Method: -- | Endpoint: -- | Status: -- | Latency: --")
        self.api_insp_meta.setStyleSheet("font-size: 12px; font-weight: 700; color: #00d4ff; background: #0c1322; padding: 7px 12px; border-radius: 6px; border-left: 4px solid #00d4ff;")
        insp_layout.addWidget(self.api_insp_meta)

        two_col_res = QHBoxLayout()
        v_col_exp = QVBoxLayout()
        v_col_exp.addWidget(QLabel("EXPECTED CRITERIA & CONTRACT:"))
        self.api_insp_expected = QTextEdit()
        self.api_insp_expected.setReadOnly(True)
        self.api_insp_expected.setMaximumHeight(65)
        self.api_insp_expected.setStyleSheet("background: #080d1a; color: #00ff9d; font-size: 11px;")
        v_col_exp.addWidget(self.api_insp_expected)
        two_col_res.addLayout(v_col_exp)

        v_col_act = QVBoxLayout()
        v_col_act.addWidget(QLabel("ACTUAL OBSERVED TELEMETRY:"))
        self.api_insp_actual = QTextEdit()
        self.api_insp_actual.setReadOnly(True)
        self.api_insp_actual.setMaximumHeight(65)
        self.api_insp_actual.setStyleSheet("background: #080d1a; color: #ffb800; font-size: 11px;")
        v_col_act.addWidget(self.api_insp_actual)
        two_col_res.addLayout(v_col_act)
        insp_layout.addLayout(two_col_res)

        insp_layout.addWidget(QLabel("REPRODUCTION CURL COMMAND:"))
        self.api_insp_curl = QTextEdit()
        self.api_insp_curl.setReadOnly(True)
        self.api_insp_curl.setMaximumHeight(65)
        self.api_insp_curl.setStyleSheet("background: #090c13; color: #a5f3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px;")
        insp_layout.addWidget(self.api_insp_curl)

        insp_layout.addWidget(QLabel("ACTIONABLE REMEDIATION & DEVELOPER FIX:"))
        self.api_insp_patch = QTextEdit()
        self.api_insp_patch.setReadOnly(True)
        self.api_insp_patch.setMaximumHeight(85)
        self.api_insp_patch.setStyleSheet("background: #0b0f16; color: #38bdf8; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px;")
        insp_layout.addWidget(self.api_insp_patch)

        # Live PoC Sandbox & Auto-Patcher Integration
        api_act_box = QHBoxLayout()
        api_act_box.setSpacing(8)
        self.btn_api_live_poc = QPushButton("▶ Run Live PoC Sandbox")
        self.btn_api_live_poc.setStyleSheet("background-color: #ff2a44; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_api_live_poc.clicked.connect(self._run_live_poc_for_api)
        api_act_box.addWidget(self.btn_api_live_poc)

        self.btn_api_autopatch = QPushButton("✨ Auto-Patcher (.patch)")
        self.btn_api_autopatch.setStyleSheet("background-color: #00ff9d; color: #0b0f19; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_api_autopatch.clicked.connect(self._show_patch_modal_for_api)
        api_act_box.addWidget(self.btn_api_autopatch)
        insp_layout.addLayout(api_act_box)

        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t1_layout = QVBoxLayout(tab_insp)
        t1_layout.setContentsMargins(0, 0, 0, 0)
        t1_layout.addWidget(insp_scroll)
        self.api_tabs.addTab(tab_insp, "🔎 Test Inspector")

        # Tab 2: Ready-to-Run Python Test Code
        tab_py = QWidget()
        py_layout = QVBoxLayout(tab_py)
        py_layout.setContentsMargins(14, 12, 14, 12)
        py_layout.setSpacing(8)

        py_top = QHBoxLayout()
        py_title = QLabel("Ready-to-Run Automation Test Suite (Python pytest + requests)")
        py_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #e4e9f2;")
        py_top.addWidget(py_title)
        py_top.addStretch()

        btn_copy_py = QPushButton("📋 Copy Python Test Suite")
        btn_copy_py.setStyleSheet("background-color: #1a2333; color: #00d4ff; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-weight: 700; font-size: 11.5px;")
        btn_copy_py.clicked.connect(self._copy_api_python_to_clipboard)
        py_top.addWidget(btn_copy_py)
        py_layout.addLayout(py_top)

        self.api_python_txt = QTextEdit()
        self.api_python_txt.setReadOnly(True)
        self.api_python_txt.setStyleSheet("background: #090c13; color: #38bdf8; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        py_layout.addWidget(self.api_python_txt)
        self.api_tabs.addTab(tab_py, "💻 Ready-to-Run Python Code")

        # Tab 3: Postman Collection v2.1.0
        tab_postman = QWidget()
        pm_layout = QVBoxLayout(tab_postman)
        pm_layout.setContentsMargins(14, 12, 14, 12)
        pm_layout.setSpacing(8)

        pm_top = QHBoxLayout()
        pm_title = QLabel("Postman Collection v2.1.0 (Import directly into Postman or run via Newman CLI)")
        pm_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #ff6b22;")
        pm_top.addWidget(pm_title)
        pm_top.addStretch()

        btn_copy_pm = QPushButton("📋 Copy Postman JSON")
        btn_copy_pm.setStyleSheet("background-color: #1a2333; color: #ff6b22; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-weight: 700; font-size: 11.5px;")
        btn_copy_pm.clicked.connect(self._copy_postman_to_clipboard)
        pm_top.addWidget(btn_copy_pm)
        pm_layout.addLayout(pm_top)

        self.api_postman_txt = QTextEdit()
        self.api_postman_txt.setReadOnly(True)
        self.api_postman_txt.setStyleSheet("background: #090c13; color: #fde047; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        pm_layout.addWidget(self.api_postman_txt)
        self.api_tabs.addTab(tab_postman, "📬 Postman Collection")

        # Tab 4: Copiable Client Deliverable Report
        tab_deliv = QWidget()
        d_layout = QVBoxLayout(tab_deliv)
        d_layout.setContentsMargins(14, 12, 14, 12)
        d_layout.setSpacing(8)

        d_top = QHBoxLayout()
        d_title = QLabel("📋 Copiable Professional API Audit Report (Ready to Send to Client / Hiring Company)")
        d_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00ff9d;")
        d_top.addWidget(d_title)
        d_top.addStretch()

        self.btn_copy_api_deliverable = QPushButton("📋 Copy Full API Report to Clipboard")
        self.btn_copy_api_deliverable.setStyleSheet("background-color: #00d4ff; color: #0b0f19; font-weight: 800; border: none; border-radius: 6px; padding: 7px 16px; font-size: 12px;")
        self.btn_copy_api_deliverable.clicked.connect(self._copy_api_report_to_clipboard)
        d_top.addWidget(self.btn_copy_api_deliverable)
        d_layout.addLayout(d_top)

        self.api_deliverable_txt = QTextEdit()
        self.api_deliverable_txt.setReadOnly(True)
        self.api_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        d_layout.addWidget(self.api_deliverable_txt)
        self.api_tabs.addTab(tab_deliv, "📋 Client Deliverable")

        splitter.addWidget(self.api_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 10: CONCURRENCY LOAD & PERFORMANCE STRESS TESTING (JMeter & k6)
    # =========================================================================
    def _setup_perf_page(self):
        layout = QVBoxLayout(self.page_perf)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header bar
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        h_title = QLabel("📈 Concurrency Load & Performance Stress Testing")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #00ff9d;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        # Load Profile Selector & VUs
        ctrl_box = QHBoxLayout()
        ctrl_box.setSpacing(8)

        lbl_prof = QLabel("Profile:")
        lbl_prof.setStyleSheet("color: #8b93a4; font-size: 11.5px; font-weight: 700;")
        ctrl_box.addWidget(lbl_prof)

        self.perf_profile_combo = QComboBox()
        self.perf_profile_combo.addItems([
            "Standard Load (50 VUs)",
            "Smoke / Sanity (5 VUs)",
            "Stress Spike (200 VUs)",
            "Soak Endurance (25 VUs)"
        ])
        self.perf_profile_combo.setStyleSheet("""
            QComboBox {
                background-color: #12151d;
                color: #f0f4fc;
                border: 1px solid #1e2434;
                border-radius: 6px;
                padding: 4px 10px;
                font-size: 11.5px;
            }
        """)
        self.perf_profile_combo.currentIndexChanged.connect(self._on_perf_profile_changed)
        ctrl_box.addWidget(self.perf_profile_combo)

        lbl_vus = QLabel("VUs:")
        lbl_vus.setStyleSheet("color: #8b93a4; font-size: 11.5px; font-weight: 700;")
        ctrl_box.addWidget(lbl_vus)

        self.perf_vus_spin = QSpinBox()
        self.perf_vus_spin.setRange(1, 1000)
        self.perf_vus_spin.setValue(50)
        self.perf_vus_spin.setStyleSheet("""
            QSpinBox {
                background-color: #12151d;
                color: #00d4ff;
                border: 1px solid #1e2434;
                border-radius: 6px;
                padding: 4px 8px;
                font-weight: 800;
                font-size: 12px;
            }
        """)
        ctrl_box.addWidget(self.perf_vus_spin)

        lbl_dur = QLabel("Duration:")
        lbl_dur.setStyleSheet("color: #8b93a4; font-size: 11.5px; font-weight: 700;")
        ctrl_box.addWidget(lbl_dur)

        self.perf_duration_spin = QSpinBox()
        self.perf_duration_spin.setRange(5, 300)
        self.perf_duration_spin.setValue(30)
        self.perf_duration_spin.setSuffix("s")
        self.perf_duration_spin.setStyleSheet("""
            QSpinBox {
                background-color: #12151d;
                color: #cbd5e1;
                border: 1px solid #1e2434;
                border-radius: 6px;
                padding: 4px 8px;
                font-weight: 700;
                font-size: 12px;
            }
        """)
        ctrl_box.addWidget(self.perf_duration_spin)

        self.btn_run_perf = QPushButton("🚀 Run Simulation")
        self.btn_run_perf.setStyleSheet("background-color: #ff2a44; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 12px;")
        self.btn_run_perf.clicked.connect(self._run_perf_simulation)
        ctrl_box.addWidget(self.btn_run_perf)

        top_row.addLayout(ctrl_box)
        header_vbox.addLayout(top_row)

        self.perf_target_lbl = QLabel("Target: Awaiting Execution | Standards: Apache JMeter 5.x & Grafana k6 | Real-Time Latency Percentiles (p50-p99)")
        self.perf_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.perf_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.perf_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)
        self.card_perf_rps = self._create_metric_card("THROUGHPUT RPS", "--", "#00ff9d")
        self.card_perf_p95 = self._create_metric_card("p95 LATENCY", "--", "#00d4ff")
        self.card_perf_avg = self._create_metric_card("AVG LATENCY", "--", "#f0f4fc")
        self.card_perf_error = self._create_metric_card("ERROR RATE", "0.0%", "#ffb800")
        self.card_perf_sla = self._create_metric_card("SLA STATUS", "--", "#00ff9d")
        self.card_perf_total = self._create_metric_card("TOTAL REQS", "0", "#a855f7")

        stats_layout.addWidget(self.card_perf_rps)
        stats_layout.addWidget(self.card_perf_p95)
        stats_layout.addWidget(self.card_perf_avg)
        stats_layout.addWidget(self.card_perf_error)
        stats_layout.addWidget(self.card_perf_sla)
        stats_layout.addWidget(self.card_perf_total)
        layout.addLayout(stats_layout)

        # Splitter: Left Tables & Telemetry, Right QTabWidget
        splitter = QSplitter(Qt.Horizontal)

        # Left Column: Latency Distribution Table & Status Codes
        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        # 1. Percentiles Table
        pct_lbl = QLabel("📊 Latency Percentile Distribution (Response Time Under Concurrency)")
        pct_lbl.setStyleSheet("font-size: 12px; font-weight: 800; color: #00d4ff;")
        left_layout.addWidget(pct_lbl)

        self.perf_percentiles_table = QTableWidget()
        self.perf_percentiles_table.setColumnCount(4)
        self.perf_percentiles_table.setHorizontalHeaderLabels(["Percentile Level", "Latency", "Industry Benchmark SLA", "SLA Gate"])
        self.perf_percentiles_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.perf_percentiles_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.perf_percentiles_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.perf_percentiles_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.perf_percentiles_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.perf_percentiles_table.setSelectionMode(QTableWidget.SingleSelection)
        self.perf_percentiles_table.setFixedHeight(210)
        left_layout.addWidget(self.perf_percentiles_table)

        # 2. HTTP Codes & Bottleneck
        bot_row = QHBoxLayout()
        bot_row.setSpacing(10)

        # HTTP Status Table
        codes_box = QVBoxLayout()
        codes_lbl = QLabel("HTTP Response Codes")
        codes_lbl.setStyleSheet("font-size: 11.5px; font-weight: 700; color: #cbd5e1;")
        codes_box.addWidget(codes_lbl)
        self.perf_codes_table = QTableWidget()
        self.perf_codes_table.setColumnCount(3)
        self.perf_codes_table.setHorizontalHeaderLabels(["Code", "Count", "Share"])
        self.perf_codes_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.perf_codes_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.perf_codes_table.setFixedHeight(120)
        codes_box.addWidget(self.perf_codes_table)
        bot_row.addLayout(codes_box, stretch=4)

        # Bottleneck Diagnosis Banner
        diag_box = QVBoxLayout()
        diag_lbl = QLabel("Capacity & Bottleneck Assessment")
        diag_lbl.setStyleSheet("font-size: 11.5px; font-weight: 700; color: #cbd5e1;")
        diag_box.addWidget(diag_lbl)
        self.perf_bottleneck_txt = QTextEdit()
        self.perf_bottleneck_txt.setReadOnly(True)
        self.perf_bottleneck_txt.setStyleSheet("background: #090c13; color: #facc15; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px; padding: 6px;")
        self.perf_bottleneck_txt.setFixedHeight(120)
        diag_box.addWidget(self.perf_bottleneck_txt)
        bot_row.addLayout(diag_box, stretch=6)

        left_layout.addLayout(bot_row)
        splitter.addWidget(left_box)

        # Right Column: 4 Tabs
        self.perf_tabs = QTabWidget()
        self.perf_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 8px 16px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #00ff9d;
                border-bottom: 2px solid #00ff9d;
            }
        """)

        # Tab 1: 📊 Latency & SLA Breakdown
        tab_sla = QWidget()
        sla_layout = QVBoxLayout(tab_sla)
        sla_layout.setContentsMargins(14, 12, 14, 12)
        sla_layout.setSpacing(10)

        sla_title = QLabel("Enterprise SLA Compliance & Architectural Diagnostics")
        sla_title.setStyleSheet("font-size: 14px; font-weight: 800; color: #00ff9d;")
        sla_layout.addWidget(sla_title)

        self.perf_sla_details_txt = QTextEdit()
        self.perf_sla_details_txt.setReadOnly(True)
        self.perf_sla_details_txt.setStyleSheet("background: #090c13; color: #e2e8f0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px; line-height: 1.5;")
        sla_layout.addWidget(self.perf_sla_details_txt)
        self.perf_tabs.addTab(tab_sla, "📊 SLA Breakdown")

        # Tab 2: 🚀 Grafana k6 Suite
        tab_k6 = QWidget()
        k6_layout = QVBoxLayout(tab_k6)
        k6_layout.setContentsMargins(14, 12, 14, 12)
        k6_layout.setSpacing(8)

        k6_top = QHBoxLayout()
        k6_title = QLabel("Grafana k6 Load Testing Script (Run with: k6 run k6_load_test.js)")
        k6_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #a855f7;")
        k6_top.addWidget(k6_title)
        k6_top.addStretch()

        self.btn_copy_k6 = QPushButton("⚡ Copy k6 Script")
        self.btn_copy_k6.setStyleSheet("background-color: #7c3aed; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_k6.clicked.connect(self._copy_k6_script)
        k6_top.addWidget(self.btn_copy_k6)

        self.btn_export_k6 = QPushButton("💾 Export k6 File")
        self.btn_export_k6.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_k6.clicked.connect(self._export_k6_script)
        k6_top.addWidget(self.btn_export_k6)
        k6_layout.addLayout(k6_top)

        self.perf_k6_txt = QTextEdit()
        self.perf_k6_txt.setReadOnly(True)
        self.perf_k6_txt.setStyleSheet("background: #090c13; color: #a5f3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        k6_layout.addWidget(self.perf_k6_txt)
        self.perf_tabs.addTab(tab_k6, "🚀 Grafana k6")

        # Tab 3: ☕ Apache JMeter XML (.jmx)
        tab_jmx = QWidget()
        jmx_layout = QVBoxLayout(tab_jmx)
        jmx_layout.setContentsMargins(14, 12, 14, 12)
        jmx_layout.setSpacing(8)

        jmx_top = QHBoxLayout()
        jmx_title = QLabel("Apache JMeter 5.x Test Plan XML (Run with: jmeter -n -t plan.jmx)")
        jmx_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #ff6b22;")
        jmx_top.addWidget(jmx_title)
        jmx_top.addStretch()

        self.btn_copy_jmeter = QPushButton("☕ Copy JMeter XML")
        self.btn_copy_jmeter.setStyleSheet("background-color: #ff6b22; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_jmeter.clicked.connect(self._copy_jmeter_jmx)
        jmx_top.addWidget(self.btn_copy_jmeter)

        self.btn_export_jmeter = QPushButton("💾 Export .JMX")
        self.btn_export_jmeter.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_jmeter.clicked.connect(self._export_jmeter_jmx)
        jmx_top.addWidget(self.btn_export_jmeter)
        jmx_layout.addLayout(jmx_top)

        self.perf_jmeter_txt = QTextEdit()
        self.perf_jmeter_txt.setReadOnly(True)
        self.perf_jmeter_txt.setStyleSheet("background: #090c13; color: #fdba74; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        jmx_layout.addWidget(self.perf_jmeter_txt)
        self.perf_tabs.addTab(tab_jmx, "☕ Apache JMeter")

        # Tab 4: 📋 Client Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(14, 12, 14, 12)
        deliv_layout.setSpacing(8)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Copiable Executive Performance Benchmark Deliverable (Markdown)")
        deliv_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00ff9d;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_perf_markdown = QPushButton("📋 Copy Client Report")
        self.btn_copy_perf_markdown.setStyleSheet("background-color: #00ff9d; color: #0b0f19; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_perf_markdown.clicked.connect(self._copy_perf_markdown)
        deliv_top.addWidget(self.btn_copy_perf_markdown)

        self.btn_export_perf_html = QPushButton("💾 Export HTML Report")
        self.btn_export_perf_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_perf_html.clicked.connect(self._export_perf_html)
        deliv_top.addWidget(self.btn_export_perf_html)
        deliv_layout.addLayout(deliv_top)

        self.perf_deliverable_txt = QTextEdit()
        self.perf_deliverable_txt.setReadOnly(True)
        self.perf_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.perf_deliverable_txt)
        self.perf_tabs.addTab(tab_deliv, "📋 Client Deliverable")

        splitter.addWidget(self.perf_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 11: CI/CD DEVOPS QUALITY GATES & PIPELINE GENERATOR
    # =========================================================================
    def _setup_cicd_page(self):
        layout = QVBoxLayout(self.page_cicd)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header bar
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(10)

        h_title = QLabel("🚀 CI/CD Automation & Quality Gate Workbench")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #a855f7;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        # Gate Rules Configuration Bar
        ctrl_box = QHBoxLayout()
        ctrl_box.setSpacing(8)

        lbl_crit = QLabel("Max Crit:")
        lbl_crit.setStyleSheet("color: #8b93a4; font-size: 11.5px; font-weight: 700;")
        ctrl_box.addWidget(lbl_crit)

        self.cicd_crit_spin = QSpinBox()
        self.cicd_crit_spin.setRange(0, 50)
        self.cicd_crit_spin.setValue(0)
        self.cicd_crit_spin.setStyleSheet("""
            QSpinBox {
                background-color: #12151d;
                color: #ff2a44;
                border: 1px solid #1e2434;
                border-radius: 6px;
                padding: 4px 8px;
                font-weight: 800;
                font-size: 12px;
            }
        """)
        ctrl_box.addWidget(self.cicd_crit_spin)

        lbl_high = QLabel("Max High:")
        lbl_high.setStyleSheet("color: #8b93a4; font-size: 11.5px; font-weight: 700;")
        ctrl_box.addWidget(lbl_high)

        self.cicd_high_spin = QSpinBox()
        self.cicd_high_spin.setRange(0, 100)
        self.cicd_high_spin.setValue(0)
        self.cicd_high_spin.setStyleSheet("""
            QSpinBox {
                background-color: #12151d;
                color: #ffb800;
                border: 1px solid #1e2434;
                border-radius: 6px;
                padding: 4px 8px;
                font-weight: 800;
                font-size: 12px;
            }
        """)
        ctrl_box.addWidget(self.cicd_high_spin)

        lbl_score = QLabel("Min Score:")
        lbl_score.setStyleSheet("color: #8b93a4; font-size: 11.5px; font-weight: 700;")
        ctrl_box.addWidget(lbl_score)

        self.cicd_score_spin = QSpinBox()
        self.cicd_score_spin.setRange(10, 100)
        self.cicd_score_spin.setValue(75)
        self.cicd_score_spin.setSuffix("%")
        self.cicd_score_spin.setStyleSheet("""
            QSpinBox {
                background-color: #12151d;
                color: #00d4ff;
                border: 1px solid #1e2434;
                border-radius: 6px;
                padding: 4px 8px;
                font-weight: 800;
                font-size: 12px;
            }
        """)
        ctrl_box.addWidget(self.cicd_score_spin)

        self.btn_eval_gate = QPushButton("⚡ Evaluate Quality Gate")
        self.btn_eval_gate.setStyleSheet("background-color: #7c3aed; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 12px;")
        self.btn_eval_gate.clicked.connect(self._evaluate_custom_gate)
        ctrl_box.addWidget(self.btn_eval_gate)

        top_row.addLayout(ctrl_box)
        header_vbox.addLayout(top_row)

        self.cicd_target_lbl = QLabel("Target: Awaiting Execution | Gating Policies: Zero-Critical, Max Highs, Min Health Score, p95 Latency SLA")
        self.cicd_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.cicd_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.cicd_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)
        self.card_cicd_status = self._create_metric_card("GATE VERDICT", "PASSED", "#00ff9d")
        self.card_cicd_score = self._create_metric_card("HEALTH SCORE", "--", "#00d4ff")
        self.card_cicd_viols = self._create_metric_card("VIOLATIONS", "0", "#ff2a44")
        self.card_cicd_crit = self._create_metric_card("CRITICAL LIMIT", "<= 0", "#f0f4fc")
        self.card_cicd_high = self._create_metric_card("HIGH LIMIT", "<= 0", "#cbd5e1")
        self.card_cicd_sla = self._create_metric_card("p95 SLA GATE", "<= 600ms", "#a855f7")

        stats_layout.addWidget(self.card_cicd_status)
        stats_layout.addWidget(self.card_cicd_score)
        stats_layout.addWidget(self.card_cicd_viols)
        stats_layout.addWidget(self.card_cicd_crit)
        stats_layout.addWidget(self.card_cicd_high)
        stats_layout.addWidget(self.card_cicd_sla)
        layout.addLayout(stats_layout)

        # Splitter: Left Findings & Remediation, Right 5-Tab Pipeline Workbench
        splitter = QSplitter(Qt.Horizontal)

        # Left Column: Policy Checklist & Remediation Actions
        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        viols_title = QLabel("📋 Automated Quality Gate Criteria & Policy Checklist")
        viols_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00d4ff;")
        left_layout.addWidget(viols_title)

        self.cicd_violations_txt = QTextEdit()
        self.cicd_violations_txt.setReadOnly(True)
        self.cicd_violations_txt.setStyleSheet("background: #090c13; color: #e2e8f0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px; padding: 8px;")
        self.cicd_violations_txt.setFixedHeight(180)
        left_layout.addWidget(self.cicd_violations_txt)

        remed_title = QLabel("🛠️ Blocking Defect Remediation & Pipeline Guidance")
        remed_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #ffb800;")
        left_layout.addWidget(remed_title)

        self.cicd_advice_txt = QTextEdit()
        self.cicd_advice_txt.setReadOnly(True)
        self.cicd_advice_txt.setStyleSheet("background: #090c13; color: #cbd5e1; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px; padding: 8px; line-height: 1.5;")
        self.cicd_advice_txt.setFixedHeight(160)
        left_layout.addWidget(self.cicd_advice_txt)

        splitter.addWidget(left_box)

        # Right Column: 5 Tabs
        self.cicd_tabs = QTabWidget()
        self.cicd_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 8px 16px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 12px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #a855f7;
                border-bottom: 2px solid #a855f7;
            }
        """)

        # Tab 1: 🐙 GitHub Actions
        tab_gh = QWidget()
        gh_layout = QVBoxLayout(tab_gh)
        gh_layout.setContentsMargins(14, 12, 14, 12)
        gh_layout.setSpacing(8)

        gh_top = QHBoxLayout()
        gh_title = QLabel("GitHub Actions Workflow (.github/workflows/quality_gate.yml)")
        gh_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #f0f4fc;")
        gh_top.addWidget(gh_title)
        gh_top.addStretch()

        self.btn_copy_github = QPushButton("🐙 Copy GitHub Actions")
        self.btn_copy_github.setStyleSheet("background-color: #238636; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_github.clicked.connect(self._copy_github_actions)
        gh_top.addWidget(self.btn_copy_github)

        self.btn_export_github = QPushButton("💾 Export .YML")
        self.btn_export_github.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_github.clicked.connect(self._export_github_workflow)
        gh_top.addWidget(self.btn_export_github)
        gh_layout.addLayout(gh_top)

        self.cicd_github_txt = QTextEdit()
        self.cicd_github_txt.setReadOnly(True)
        self.cicd_github_txt.setStyleSheet("background: #090c13; color: #a5f3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        gh_layout.addWidget(self.cicd_github_txt)
        self.cicd_tabs.addTab(tab_gh, "🐙 GitHub Actions")

        # Tab 2: 🦊 GitLab CI
        tab_gl = QWidget()
        gl_layout = QVBoxLayout(tab_gl)
        gl_layout.setContentsMargins(14, 12, 14, 12)
        gl_layout.setSpacing(8)

        gl_top = QHBoxLayout()
        gl_title = QLabel("GitLab CI/CD Pipeline Configuration (.gitlab-ci.yml)")
        gl_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #fc6d26;")
        gl_top.addWidget(gl_title)
        gl_top.addStretch()

        self.btn_copy_gitlab = QPushButton("🦊 Copy GitLab CI")
        self.btn_copy_gitlab.setStyleSheet("background-color: #fc6d26; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_gitlab.clicked.connect(self._copy_gitlab_ci)
        gl_top.addWidget(self.btn_copy_gitlab)

        self.btn_export_gitlab = QPushButton("💾 Export .gitlab-ci.yml")
        self.btn_export_gitlab.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_gitlab.clicked.connect(self._export_gitlab_pipeline)
        gl_top.addWidget(self.btn_export_gitlab)
        gl_layout.addLayout(gl_top)

        self.cicd_gitlab_txt = QTextEdit()
        self.cicd_gitlab_txt.setReadOnly(True)
        self.cicd_gitlab_txt.setStyleSheet("background: #090c13; color: #fed7aa; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        gl_layout.addWidget(self.cicd_gitlab_txt)
        self.cicd_tabs.addTab(tab_gl, "🦊 GitLab CI")

        # Tab 3: 🤵 Jenkins
        tab_jk = QWidget()
        jk_layout = QVBoxLayout(tab_jk)
        jk_layout.setContentsMargins(14, 12, 14, 12)
        jk_layout.setSpacing(8)

        jk_top = QHBoxLayout()
        jk_title = QLabel("Jenkins Declarative Pipeline (Jenkinsfile)")
        jk_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00d4ff;")
        jk_top.addWidget(jk_title)
        jk_top.addStretch()

        self.btn_copy_jenkins = QPushButton("🤵 Copy Jenkinsfile")
        self.btn_copy_jenkins.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_jenkins.clicked.connect(self._copy_jenkinsfile)
        jk_top.addWidget(self.btn_copy_jenkins)

        self.btn_export_jenkins = QPushButton("💾 Export Jenkinsfile")
        self.btn_export_jenkins.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_jenkins.clicked.connect(self._export_jenkinsfile)
        jk_top.addWidget(self.btn_export_jenkins)
        jk_layout.addLayout(jk_top)

        self.cicd_jenkins_txt = QTextEdit()
        self.cicd_jenkins_txt.setReadOnly(True)
        self.cicd_jenkins_txt.setStyleSheet("background: #090c13; color: #bae6fd; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        jk_layout.addWidget(self.cicd_jenkins_txt)
        self.cicd_tabs.addTab(tab_jk, "🤵 Jenkins")

        # Tab 4: 📑 JUnit XML
        tab_junit = QWidget()
        junit_layout = QVBoxLayout(tab_junit)
        junit_layout.setContentsMargins(14, 12, 14, 12)
        junit_layout.setSpacing(8)

        junit_top = QHBoxLayout()
        junit_title = QLabel("Universal JUnit XML Test Deliverable (junit_results.xml)")
        junit_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00ff9d;")
        junit_top.addWidget(junit_title)
        junit_top.addStretch()

        self.btn_copy_junit = QPushButton("📑 Copy JUnit XML")
        self.btn_copy_junit.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_junit.clicked.connect(self._copy_junit_xml)
        junit_top.addWidget(self.btn_copy_junit)

        self.btn_export_junit = QPushButton("💾 Export .XML")
        self.btn_export_junit.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_junit.clicked.connect(self._export_junit_xml)
        junit_top.addWidget(self.btn_export_junit)
        junit_layout.addLayout(junit_top)

        self.cicd_junit_txt = QTextEdit()
        self.cicd_junit_txt.setReadOnly(True)
        self.cicd_junit_txt.setStyleSheet("background: #090c13; color: #bbf7d0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        junit_layout.addWidget(self.cicd_junit_txt)
        self.cicd_tabs.addTab(tab_junit, "📑 JUnit XML")

        # Tab 5: 📋 Client Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(14, 12, 14, 12)
        deliv_layout.setSpacing(8)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Copiable Executive CI/CD Quality Gate Deliverable (Markdown)")
        deliv_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00ff9d;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_cicd_markdown = QPushButton("📋 Copy Client Report")
        self.btn_copy_cicd_markdown.setStyleSheet("background-color: #00ff9d; color: #0b0f19; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_cicd_markdown.clicked.connect(self._copy_cicd_markdown)
        deliv_top.addWidget(self.btn_copy_cicd_markdown)

        self.btn_export_cicd_html = QPushButton("💾 Export HTML Report")
        self.btn_export_cicd_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 6px 14px; font-size: 11.5px; font-weight: 700;")
        self.btn_export_cicd_html.clicked.connect(self._export_cicd_html)
        deliv_top.addWidget(self.btn_export_cicd_html)
        deliv_layout.addLayout(deliv_top)

        self.cicd_deliverable_txt = QTextEdit()
        self.cicd_deliverable_txt.setReadOnly(True)
        self.cicd_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.cicd_deliverable_txt)
        self.cicd_tabs.addTab(tab_deliv, "📋 Client Deliverable")

        splitter.addWidget(self.cicd_tabs)
        splitter.setStretchFactor(0, 4)
        splitter.setStretchFactor(1, 6)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 12: DATABASE SCHEMA, INDEX OPTIMIZATION & DATA INTEGRITY
    # =========================================================================
    def _setup_db_page(self):
        layout = QVBoxLayout(self.page_db)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # Header bar
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        h_title = QLabel("🗄️ Database Schema & Data Integrity Workbench")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #38bdf8;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        # Action Buttons
        self.btn_copy_db_markdown = QPushButton("📋 Copy Report")
        self.btn_copy_db_markdown.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_db_markdown.clicked.connect(self._copy_db_markdown)
        top_row.addWidget(self.btn_copy_db_markdown)

        self.btn_export_db_sql = QPushButton("💾 Export SQL")
        self.btn_export_db_sql.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_export_db_sql.clicked.connect(self._export_db_sql)
        top_row.addWidget(self.btn_export_db_sql)

        self.btn_export_db_html = QPushButton("💾 Export HTML")
        self.btn_export_db_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 700;")
        self.btn_export_db_html.clicked.connect(self._export_db_html)
        top_row.addWidget(self.btn_export_db_html)

        self.btn_rerun_db = QPushButton("🔄 Re-run")
        self.btn_rerun_db.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_rerun_db.clicked.connect(self._rerun_db_audit)
        top_row.addWidget(self.btn_rerun_db)

        header_vbox.addLayout(top_row)

        self.db_target_lbl = QLabel("Target: Awaiting Execution | Audit: Schema constraints, unindexed foreign keys, orphan cascades, and ACID isolation")
        self.db_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.db_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.db_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(10)
        self.card_db_score = self._create_metric_card("INTEGRITY SCORE", "--", "#00ff9d")
        self.card_db_tables = self._create_metric_card("TABLES CHECKED", "0", "#00d4ff")
        self.card_db_checks = self._create_metric_card("CHECKS RUN", "0", "#f0f4fc")
        self.card_db_defects = self._create_metric_card("SCHEMA DEFECTS", "0", "#ff2a44")
        self.card_db_warnings = self._create_metric_card("WARNINGS", "0", "#ffb800")
        self.card_db_engine = self._create_metric_card("DATABASE ENGINE", "RDBMS", "#a855f7")

        stats_layout.addWidget(self.card_db_score)
        stats_layout.addWidget(self.card_db_tables)
        stats_layout.addWidget(self.card_db_checks)
        stats_layout.addWidget(self.card_db_defects)
        stats_layout.addWidget(self.card_db_warnings)
        stats_layout.addWidget(self.card_db_engine)
        layout.addLayout(stats_layout)

        # Filter bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(6)
        self.btn_fltr_db_all = QPushButton("All Checks")
        self.btn_fltr_db_schema = QPushButton("Schema & Constraints")
        self.btn_fltr_db_indexes = QPushButton("Index Traps")
        self.btn_fltr_db_integrity = QPushButton("Data Integrity")
        self.btn_fltr_db_acid = QPushButton("ACID Concurrency")
        self.btn_fltr_db_sqli = QPushButton("SQL Defense")

        for btn in (self.btn_fltr_db_all, self.btn_fltr_db_schema, self.btn_fltr_db_indexes, self.btn_fltr_db_integrity, self.btn_fltr_db_acid, self.btn_fltr_db_sqli):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 12px; font-size: 11.5px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_db_all.clicked.connect(lambda: self._filter_db_defects("all"))
        self.btn_fltr_db_schema.clicked.connect(lambda: self._filter_db_defects("schema"))
        self.btn_fltr_db_indexes.clicked.connect(lambda: self._filter_db_defects("indexes"))
        self.btn_fltr_db_integrity.clicked.connect(lambda: self._filter_db_defects("integrity"))
        self.btn_fltr_db_acid.clicked.connect(lambda: self._filter_db_defects("acid"))
        self.btn_fltr_db_sqli.clicked.connect(lambda: self._filter_db_defects("sqli"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Tables & Defect Matrix, Right Tabs
        splitter = QSplitter(Qt.Horizontal)

        # Left Column: Tables & Defects
        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        # 1. Tables Directory
        tbls_title = QLabel("🗂️ Active Entity Schema & Indexing Directory")
        tbls_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #38bdf8;")
        left_layout.addWidget(tbls_title)

        self.db_tables_table = QTableWidget()
        self.db_tables_table.setColumnCount(5)
        self.db_tables_table.setHorizontalHeaderLabels(["Table Name", "Columns", "Est. Records", "Primary Key", "Unindexed Foreign Keys"])
        self.db_tables_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.db_tables_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.db_tables_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.db_tables_table.setFixedHeight(140)
        left_layout.addWidget(self.db_tables_table)

        # 2. Defect Matrix
        defects_title = QLabel("🔎 Data Integrity, Constraint & ACID Defect Matrix")
        defects_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #ffb800;")
        left_layout.addWidget(defects_title)

        self.db_defects_table = QTableWidget()
        self.db_defects_table.setColumnCount(6)
        self.db_defects_table.setHorizontalHeaderLabels(["ID", "Category", "Severity", "Status", "Title", "Entity"])
        self.db_defects_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.db_defects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.db_defects_table.setSelectionMode(QTableWidget.SingleSelection)
        self.db_defects_table.itemSelectionChanged.connect(self._on_db_defect_selected)
        left_layout.addWidget(self.db_defects_table)

        splitter.addWidget(left_box)

        # Right Column: 3 Tabs
        self.db_tabs = QTabWidget()
        self.db_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 5px 8px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #38bdf8;
                border-bottom: 2px solid #38bdf8;
            }
        """)

        # Tab 0: 🔎 Defect Inspector wrapped in QScrollArea
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_scroll.setFrameShape(QFrame.NoFrame)
        insp_scroll.setStyleSheet("background: transparent; border: none;")

        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(12, 10, 12, 10)
        insp_layout.setSpacing(7)

        self.db_insp_title = QLabel("Select a database check from the matrix to inspect details.")
        self.db_insp_title.setStyleSheet("font-size: 13.5px; font-weight: 800; color: #38bdf8;")
        self.db_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.db_insp_title)

        self.db_insp_desc = QLabel("Description: --")
        self.db_insp_desc.setStyleSheet("font-size: 11.5px; color: #cbd5e1; line-height: 1.3;")
        self.db_insp_desc.setWordWrap(True)
        insp_layout.addWidget(self.db_insp_desc)

        self.db_insp_impact = QLabel("Impact: --")
        self.db_insp_impact.setStyleSheet("font-size: 11.5px; color: #ffb800; line-height: 1.3;")
        self.db_insp_impact.setWordWrap(True)
        insp_layout.addWidget(self.db_insp_impact)

        patch_lbl = QLabel("Remediation DDL / SQL Patch:")
        patch_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #00ff9d;")
        insp_layout.addWidget(patch_lbl)

        self.db_insp_sql = QTextEdit()
        self.db_insp_sql.setReadOnly(True)
        self.db_insp_sql.setStyleSheet("background: #090c13; color: #a5f3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.db_insp_sql.setMinimumHeight(100)
        self.db_insp_sql.setMaximumHeight(200)
        insp_layout.addWidget(self.db_insp_sql)
        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t_insp_layout = QVBoxLayout(tab_insp)
        t_insp_layout.setContentsMargins(0, 0, 0, 0)
        t_insp_layout.addWidget(insp_scroll)
        self.db_tabs.addTab(tab_insp, "🔎 Inspector")

        # Tab 2: 💾 SQL Migration Script
        tab_sql = QWidget()
        sql_layout = QVBoxLayout(tab_sql)
        sql_layout.setContentsMargins(14, 12, 14, 12)
        sql_layout.setSpacing(8)

        sql_top = QHBoxLayout()
        sql_title = QLabel("Idempotent DDL Remediation Migration (Apply in Staging / CI)")
        sql_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00ff9d;")
        sql_top.addWidget(sql_title)
        sql_top.addStretch()

        self.btn_copy_db_sql = QPushButton("💾 Copy SQL Patch")
        self.btn_copy_db_sql.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_db_sql.clicked.connect(self._copy_db_sql)
        sql_top.addWidget(self.btn_copy_db_sql)
        sql_layout.addLayout(sql_top)

        self.db_sql_txt = QTextEdit()
        self.db_sql_txt.setReadOnly(True)
        self.db_sql_txt.setStyleSheet("background: #090c13; color: #6ee7b7; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        sql_layout.addWidget(self.db_sql_txt)
        self.db_tabs.addTab(tab_sql, "💾 SQL Migration")

        # Tab 3: 📋 Client Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(14, 12, 14, 12)
        deliv_layout.setSpacing(8)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Copiable Executive Database Quality Deliverable (Markdown)")
        deliv_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #38bdf8;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_db_deliverable = QPushButton("📋 Copy Full Report")
        self.btn_copy_db_deliverable.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_db_deliverable.clicked.connect(self._copy_db_markdown)
        deliv_top.addWidget(self.btn_copy_db_deliverable)
        deliv_layout.addLayout(deliv_top)

        self.db_deliverable_txt = QTextEdit()
        self.db_deliverable_txt.setReadOnly(True)
        self.db_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.db_deliverable_txt)
        self.db_tabs.addTab(tab_deliv, "📋 Client Deliverable")

        splitter.addWidget(self.db_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 13: MULTI-DEVICE VIEWPORT & WCAG ACCESSIBILITY WORKBENCH
    # =========================================================================
    def _setup_compat_page(self):
        layout = QVBoxLayout(self.page_compat)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Top bar with Titles and Action buttons
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        h_title = QLabel("📱 Responsive Viewports & Multi-Device Workbench")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #38bdf8;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        self.btn_copy_compat_markdown = QPushButton("📋 Copy Report")
        self.btn_copy_compat_markdown.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_compat_markdown.clicked.connect(self._copy_compat_markdown)
        top_row.addWidget(self.btn_copy_compat_markdown)

        self.btn_copy_playwright_matrix = QPushButton("⚡ Playwright Suite")
        self.btn_copy_playwright_matrix.setStyleSheet("background-color: #8b5cf6; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_playwright_matrix.clicked.connect(self._copy_compat_playwright)
        top_row.addWidget(self.btn_copy_playwright_matrix)

        self.btn_export_compat_html = QPushButton("💾 Export HTML")
        self.btn_export_compat_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 700;")
        self.btn_export_compat_html.clicked.connect(self._export_compat_html)
        top_row.addWidget(self.btn_export_compat_html)

        self.btn_rerun_compat = QPushButton("🔄 Re-run")
        self.btn_rerun_compat.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_rerun_compat.clicked.connect(self._rerun_compat_audit)
        top_row.addWidget(self.btn_rerun_compat)

        header_vbox.addLayout(top_row)

        self.compat_target_lbl = QLabel("Target: Awaiting Execution | Audit: Multi-device reflow, horizontal overflow, touch target ergonomics, and WCAG 2.1 AA contrast")
        self.compat_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.compat_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.compat_target_lbl)

        layout.addLayout(header_vbox)

        # 6 Metric KPI Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)
        self.card_compat_score = self._create_metric_card("COMPATIBILITY SCORE", "--", "#00ff9d")
        self.card_compat_viewports = self._create_metric_card("VIEWPORTS TESTED", "0", "#00d4ff")
        self.card_compat_checks = self._create_metric_card("CHECKS RUN", "0", "#f0f4fc")
        self.card_compat_defects = self._create_metric_card("LAYOUT DEFECTS", "0", "#ff2a44")
        self.card_compat_warnings = self._create_metric_card("A11Y WARNINGS", "0", "#ffb800")
        self.card_compat_status = self._create_metric_card("WCAG STATUS", "STANDBY", "#a855f7")

        stats_layout.addWidget(self.card_compat_score)
        stats_layout.addWidget(self.card_compat_viewports)
        stats_layout.addWidget(self.card_compat_checks)
        stats_layout.addWidget(self.card_compat_defects)
        stats_layout.addWidget(self.card_compat_warnings)
        stats_layout.addWidget(self.card_compat_status)
        layout.addLayout(stats_layout)

        # Filter bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(5)
        self.btn_fltr_compat_all = QPushButton("All")
        self.btn_fltr_compat_layout = QPushButton("Layout")
        self.btn_fltr_compat_touch = QPushButton("Touch")
        self.btn_fltr_compat_contrast = QPushButton("Contrast")
        self.btn_fltr_compat_forms = QPushButton("Forms")
        self.btn_fltr_compat_defects = QPushButton("Defects Only")

        for btn in (self.btn_fltr_compat_all, self.btn_fltr_compat_layout, self.btn_fltr_compat_touch, self.btn_fltr_compat_contrast, self.btn_fltr_compat_forms, self.btn_fltr_compat_defects):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 4px 9px; font-size: 11px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_compat_all.clicked.connect(lambda: self._filter_compat_defects("all"))
        self.btn_fltr_compat_layout.clicked.connect(lambda: self._filter_compat_defects("layout"))
        self.btn_fltr_compat_touch.clicked.connect(lambda: self._filter_compat_defects("touch"))
        self.btn_fltr_compat_contrast.clicked.connect(lambda: self._filter_compat_defects("contrast"))
        self.btn_fltr_compat_forms.clicked.connect(lambda: self._filter_compat_defects("forms"))
        self.btn_fltr_compat_defects.clicked.connect(lambda: self._filter_compat_defects("defects_only"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Devices & Defects, Right Tabs
        splitter = QSplitter(Qt.Horizontal)

        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        # 1. Device Simulation Matrix
        dev_title = QLabel("📱 Multi-Device Viewport Simulation Matrix")
        dev_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #38bdf8;")
        left_layout.addWidget(dev_title)

        self.compat_devices_table = QTableWidget()
        self.compat_devices_table.setColumnCount(7)
        self.compat_devices_table.setHorizontalHeaderLabels(["Device Name", "Category", "Viewport", "DPR", "Status", "Overflow", "Touch Hazards"])
        self.compat_devices_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.compat_devices_table.horizontalHeader().setSectionResizeMode(6, QHeaderView.Stretch)
        self.compat_devices_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.compat_devices_table.setFixedHeight(120)
        left_layout.addWidget(self.compat_devices_table)

        # 2. Defect Matrix
        defects_title = QLabel("🔎 Responsive Layout & Accessibility Defect Matrix")
        defects_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #ffb800;")
        left_layout.addWidget(defects_title)

        self.compat_defects_table = QTableWidget()
        self.compat_defects_table.setColumnCount(6)
        self.compat_defects_table.setHorizontalHeaderLabels(["ID", "Category", "Severity", "Status", "Title", "Viewports"])
        self.compat_defects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.compat_defects_table.setColumnWidth(0, 80)
        self.compat_defects_table.setColumnWidth(1, 90)
        self.compat_defects_table.setColumnWidth(2, 65)
        self.compat_defects_table.setColumnWidth(3, 65)
        self.compat_defects_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.compat_defects_table.setColumnWidth(5, 95)
        self.compat_defects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.compat_defects_table.setSelectionMode(QTableWidget.SingleSelection)
        self.compat_defects_table.itemSelectionChanged.connect(self._on_compat_defect_selected)
        left_layout.addWidget(self.compat_defects_table)

        splitter.addWidget(left_box)

        # Right Column: 4 Tabs
        self.compat_tabs = QTabWidget()
        self.compat_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 5px 8px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #38bdf8;
                border-bottom: 2px solid #38bdf8;
            }
        """)

        # Tab 0: 🔎 Defect Inspector wrapped in QScrollArea
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_scroll.setFrameShape(QFrame.NoFrame)
        insp_scroll.setStyleSheet("background: transparent; border: none;")

        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(12, 10, 12, 10)
        insp_layout.setSpacing(7)

        self.compat_insp_title = QLabel("Select a layout or A11y defect to inspect remediation.")
        self.compat_insp_title.setStyleSheet("font-size: 13.5px; font-weight: 800; color: #38bdf8;")
        self.compat_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.compat_insp_title)

        self.compat_insp_meta = QLabel("Criterion: -- | Viewports: --")
        self.compat_insp_meta.setStyleSheet("font-size: 11.5px; color: #a78bfa; font-weight: 700;")
        insp_layout.addWidget(self.compat_insp_meta)

        self.compat_insp_desc = QLabel("Description: --")
        self.compat_insp_desc.setStyleSheet("font-size: 11.5px; color: #cbd5e1; line-height: 1.3;")
        self.compat_insp_desc.setWordWrap(True)
        insp_layout.addWidget(self.compat_insp_desc)

        self.compat_insp_impact = QLabel("Impact: --")
        self.compat_insp_impact.setStyleSheet("font-size: 11.5px; color: #fca5a5; line-height: 1.3;")
        self.compat_insp_impact.setWordWrap(True)
        insp_layout.addWidget(self.compat_insp_impact)

        patch_lbl = QLabel("CSS / HTML Remediation Code:")
        patch_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #00ff9d;")
        insp_layout.addWidget(patch_lbl)

        self.compat_insp_code = QTextEdit()
        self.compat_insp_code.setReadOnly(True)
        self.compat_insp_code.setStyleSheet("background: #090c13; color: #a5f3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.compat_insp_code.setMinimumHeight(100)
        self.compat_insp_code.setMaximumHeight(200)
        insp_layout.addWidget(self.compat_insp_code)
        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t_insp_layout = QVBoxLayout(tab_insp)
        t_insp_layout.setContentsMargins(0, 0, 0, 0)
        t_insp_layout.addWidget(insp_scroll)
        self.compat_tabs.addTab(tab_insp, "🔎 Inspector")

        # Tab 1: 🎭 Playwright Multi-Device Matrix
        tab_pw = QWidget()
        pw_layout = QVBoxLayout(tab_pw)
        pw_layout.setContentsMargins(14, 12, 14, 12)
        pw_layout.setSpacing(8)

        pw_top = QHBoxLayout()
        pw_title = QLabel("Playwright Multi-Device Matrix Runner (pytest test_matrix.py)")
        pw_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #8b5cf6;")
        pw_top.addWidget(pw_title)
        pw_top.addStretch()

        self.btn_copy_compat_pw = QPushButton("🎭 Copy Playwright Script")
        self.btn_copy_compat_pw.setStyleSheet("background-color: #8b5cf6; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_compat_pw.clicked.connect(self._copy_compat_playwright)
        pw_top.addWidget(self.btn_copy_compat_pw)
        pw_layout.addLayout(pw_top)

        self.compat_pw_txt = QTextEdit()
        self.compat_pw_txt.setReadOnly(True)
        self.compat_pw_txt.setStyleSheet("background: #090c13; color: #c4b5fd; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        pw_layout.addWidget(self.compat_pw_txt)
        self.compat_tabs.addTab(tab_pw, "🎭 Playwright")

        # Tab 2: 🌲 Cypress Viewport Reflow
        tab_cy = QWidget()
        cy_layout = QVBoxLayout(tab_cy)
        cy_layout.setContentsMargins(14, 12, 14, 12)
        cy_layout.setSpacing(8)

        cy_top = QHBoxLayout()
        cy_title = QLabel("Cypress Multi-Device Viewport Reflow Spec (viewport-test.spec.js)")
        cy_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #00d4ff;")
        cy_top.addWidget(cy_title)
        cy_top.addStretch()

        self.btn_copy_compat_cy = QPushButton("🌲 Copy Cypress Spec")
        self.btn_copy_compat_cy.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_compat_cy.clicked.connect(self._copy_compat_cypress)
        cy_top.addWidget(self.btn_copy_compat_cy)
        cy_layout.addLayout(cy_top)

        self.compat_cy_txt = QTextEdit()
        self.compat_cy_txt.setReadOnly(True)
        self.compat_cy_txt.setStyleSheet("background: #090c13; color: #7dd3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        cy_layout.addWidget(self.compat_cy_txt)
        self.compat_tabs.addTab(tab_cy, "🌲 Cypress")

        # Tab 3: 📋 Client Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(14, 12, 14, 12)
        deliv_layout.setSpacing(8)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Copiable Executive Deliverable (Ready to Send to Client / Hiring Manager)")
        deliv_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #38bdf8;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_compat_deliv = QPushButton("📋 Copy Full Report")
        self.btn_copy_compat_deliv.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_compat_deliv.clicked.connect(self._copy_compat_markdown)
        deliv_top.addWidget(self.btn_copy_compat_deliv)
        deliv_layout.addLayout(deliv_top)

        self.compat_deliverable_txt = QTextEdit()
        self.compat_deliverable_txt.setReadOnly(True)
        self.compat_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.compat_deliverable_txt)
        self.compat_tabs.addTab(tab_deliv, "📋 Deliverable")

        splitter.addWidget(self.compat_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # PAGE 14: NETWORK PROTOCOL, TLS CIPHERS & CERTIFICATE WORKBENCH
    # =========================================================================
    def _setup_network_page(self):
        layout = QVBoxLayout(self.page_network)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Top bar with Titles and Action buttons
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        h_title = QLabel("🔐 Network Protocol, TLS/SSL & Cryptography Workbench")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #38bdf8;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        self.btn_copy_net_markdown = QPushButton("📋 Copy Report")
        self.btn_copy_net_markdown.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_net_markdown.clicked.connect(self._copy_net_markdown)
        top_row.addWidget(self.btn_copy_net_markdown)

        self.btn_copy_openssl = QPushButton("⚡ OpenSSL Script")
        self.btn_copy_openssl.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_openssl.clicked.connect(self._copy_openssl_script)
        top_row.addWidget(self.btn_copy_openssl)

        self.btn_export_net_html = QPushButton("💾 Export HTML")
        self.btn_export_net_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 700;")
        self.btn_export_net_html.clicked.connect(self._export_net_html)
        top_row.addWidget(self.btn_export_net_html)

        self.btn_rerun_net = QPushButton("🔄 Re-run")
        self.btn_rerun_net.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_rerun_net.clicked.connect(self._rerun_net_audit)
        top_row.addWidget(self.btn_rerun_net)

        header_vbox.addLayout(top_row)

        self.net_target_lbl = QLabel("Target: Awaiting Execution | Audit: TLS 1.3/1.2 cipher suites, PFS, X.509 certificate chain, OCSP stapling, and DNS perimeter security")
        self.net_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.net_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.net_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Metric Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)
        self.card_net_score = self._create_metric_card("CRYPTO SCORE", "--", "#00ff9d")
        self.card_net_grade = self._create_metric_card("TLS GRADE", "--", "#00d4ff")
        self.card_net_protocol = self._create_metric_card("PROTOCOL", "TLSv1.3", "#38bdf8")
        self.card_net_cert_days = self._create_metric_card("CERT EXPIRY", "--", "#a855f7")
        self.card_net_defects = self._create_metric_card("CRYPTO DEFECTS", "0", "#ff2a44")
        self.card_net_warnings = self._create_metric_card("WARNINGS", "0", "#ffb800")

        stats_layout.addWidget(self.card_net_score)
        stats_layout.addWidget(self.card_net_grade)
        stats_layout.addWidget(self.card_net_protocol)
        stats_layout.addWidget(self.card_net_cert_days)
        stats_layout.addWidget(self.card_net_defects)
        stats_layout.addWidget(self.card_net_warnings)
        layout.addLayout(stats_layout)

        # Filter bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(5)
        self.btn_fltr_net_all = QPushButton("All")
        self.btn_fltr_net_protocol = QPushButton("TLS Protocol")
        self.btn_fltr_net_ciphers = QPushButton("Ciphers")
        self.btn_fltr_net_cert = QPushButton("Cert Health")
        self.btn_fltr_net_dns = QPushButton("DNS/Spoof")
        self.btn_fltr_net_defects = QPushButton("Defects Only")

        for btn in (self.btn_fltr_net_all, self.btn_fltr_net_protocol, self.btn_fltr_net_ciphers, self.btn_fltr_net_cert, self.btn_fltr_net_dns, self.btn_fltr_net_defects):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 4px 9px; font-size: 11px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_net_all.clicked.connect(lambda: self._filter_net_defects("all"))
        self.btn_fltr_net_protocol.clicked.connect(lambda: self._filter_net_defects("protocol"))
        self.btn_fltr_net_ciphers.clicked.connect(lambda: self._filter_net_defects("ciphers"))
        self.btn_fltr_net_cert.clicked.connect(lambda: self._filter_net_defects("cert"))
        self.btn_fltr_net_dns.clicked.connect(lambda: self._filter_net_defects("dns"))
        self.btn_fltr_net_defects.clicked.connect(lambda: self._filter_net_defects("defects_only"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Telemetry & Defects, Right Tabs
        splitter = QSplitter(Qt.Horizontal)

        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        # 1. Telemetry Table
        tel_title = QLabel("🔐 Cryptographic Handshake & Certificate Telemetry")
        tel_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #38bdf8;")
        left_layout.addWidget(tel_title)

        self.net_telemetry_table = QTableWidget()
        self.net_telemetry_table.setColumnCount(2)
        self.net_telemetry_table.setHorizontalHeaderLabels(["Security Attribute", "Evaluated Handshake State"])
        self.net_telemetry_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.net_telemetry_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.net_telemetry_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.net_telemetry_table.setFixedHeight(120)
        left_layout.addWidget(self.net_telemetry_table)

        # 2. Defect Matrix
        defects_title = QLabel("🔎 Cryptographic, Protocol & Boundary Defect Matrix")
        defects_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #ffb800;")
        left_layout.addWidget(defects_title)

        self.net_defects_table = QTableWidget()
        self.net_defects_table.setColumnCount(6)
        self.net_defects_table.setHorizontalHeaderLabels(["ID", "Category", "Severity", "Status", "Title", "Component"])
        self.net_defects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.net_defects_table.setColumnWidth(0, 80)
        self.net_defects_table.setColumnWidth(1, 90)
        self.net_defects_table.setColumnWidth(2, 65)
        self.net_defects_table.setColumnWidth(3, 65)
        self.net_defects_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.net_defects_table.setColumnWidth(5, 95)
        self.net_defects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.net_defects_table.setSelectionMode(QTableWidget.SingleSelection)
        self.net_defects_table.itemSelectionChanged.connect(self._on_net_defect_selected)
        left_layout.addWidget(self.net_defects_table)

        splitter.addWidget(left_box)

        # Right Column: 3 Tabs
        self.net_tabs = QTabWidget()
        self.net_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 5px 8px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #38bdf8;
                border-bottom: 2px solid #38bdf8;
            }
        """)

        # Tab 0: 🔎 Defect Inspector wrapped in QScrollArea
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_scroll.setFrameShape(QFrame.NoFrame)
        insp_scroll.setStyleSheet("background: transparent; border: none;")

        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(12, 10, 12, 10)
        insp_layout.setSpacing(7)

        self.net_insp_title = QLabel("Select a cryptographic check to inspect remediation.")
        self.net_insp_title.setStyleSheet("font-size: 13.5px; font-weight: 800; color: #38bdf8;")
        self.net_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.net_insp_title)

        self.net_insp_meta = QLabel("Component: -- | Category: --")
        self.net_insp_meta.setStyleSheet("font-size: 11.5px; color: #38bdf8; font-weight: 700;")
        insp_layout.addWidget(self.net_insp_meta)

        self.net_insp_desc = QLabel("Description: --")
        self.net_insp_desc.setStyleSheet("font-size: 11.5px; color: #cbd5e1; line-height: 1.3;")
        self.net_insp_desc.setWordWrap(True)
        insp_layout.addWidget(self.net_insp_desc)

        self.net_insp_impact = QLabel("Impact: --")
        self.net_insp_impact.setStyleSheet("font-size: 11.5px; color: #fca5a5; line-height: 1.3;")
        self.net_insp_impact.setWordWrap(True)
        insp_layout.addWidget(self.net_insp_impact)

        patch_lbl = QLabel("Remediation Server Configuration / DNS Patch:")
        patch_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #00ff9d;")
        insp_layout.addWidget(patch_lbl)

        self.net_insp_code = QTextEdit()
        self.net_insp_code.setReadOnly(True)
        self.net_insp_code.setStyleSheet("background: #090c13; color: #a5f3fc; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.net_insp_code.setMinimumHeight(100)
        self.net_insp_code.setMaximumHeight(200)
        insp_layout.addWidget(self.net_insp_code)
        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t_insp_layout = QVBoxLayout(tab_insp)
        t_insp_layout.setContentsMargins(0, 0, 0, 0)
        t_insp_layout.addWidget(insp_scroll)
        self.net_tabs.addTab(tab_insp, "🔎 Inspector")

        # Tab 1: ⚡ OpenSSL Diagnostic Script
        tab_ssl = QWidget()
        ssl_layout = QVBoxLayout(tab_ssl)
        ssl_layout.setContentsMargins(12, 10, 12, 10)
        ssl_layout.setSpacing(6)

        ssl_top = QHBoxLayout()
        ssl_title = QLabel("Automated OpenSSL Command-Line Diagnostic Suite")
        ssl_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #059669;")
        ssl_top.addWidget(ssl_title)
        ssl_top.addStretch()

        self.btn_copy_net_ssl = QPushButton("⚡ Copy Script")
        self.btn_copy_net_ssl.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 4px 11px; font-size: 11px;")
        self.btn_copy_net_ssl.clicked.connect(self._copy_openssl_script)
        ssl_top.addWidget(self.btn_copy_net_ssl)
        ssl_layout.addLayout(ssl_top)

        self.net_openssl_txt = QTextEdit()
        self.net_openssl_txt.setReadOnly(True)
        self.net_openssl_txt.setStyleSheet("background: #090c13; color: #86efac; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        ssl_layout.addWidget(self.net_openssl_txt)
        self.net_tabs.addTab(tab_ssl, "⚡ OpenSSL Suite")

        # Tab 2: 📋 Client Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(12, 10, 12, 10)
        deliv_layout.setSpacing(6)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Executive Cryptographic & Network Deliverable (Markdown)")
        deliv_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #38bdf8;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_net_deliv = QPushButton("📋 Copy Deliverable")
        self.btn_copy_net_deliv.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 4px 11px; font-size: 11px;")
        self.btn_copy_net_deliv.clicked.connect(self._copy_net_markdown)
        deliv_top.addWidget(self.btn_copy_net_deliv)
        deliv_layout.addLayout(deliv_top)

        self.net_deliverable_txt = QTextEdit()
        self.net_deliverable_txt.setReadOnly(True)
        self.net_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.net_deliverable_txt)
        self.net_tabs.addTab(tab_deliv, "📋 Deliverable")

        splitter.addWidget(self.net_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

        splitter.addWidget(self.net_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    def _setup_logic_page(self):
        layout = QVBoxLayout(self.page_logic)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header bar
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        h_title = QLabel("💼 Business Logic & State Machine Workbench")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #a855f7;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        self.btn_copy_logic_markdown = QPushButton("📋 Copy Report")
        self.btn_copy_logic_markdown.setStyleSheet("background-color: #7c3aed; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_logic_markdown.clicked.connect(self._copy_logic_markdown)
        top_row.addWidget(self.btn_copy_logic_markdown)

        self.btn_copy_pytest_logic = QPushButton("⚡ Pytest Suite")
        self.btn_copy_pytest_logic.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_pytest_logic.clicked.connect(self._copy_pytest_logic)
        top_row.addWidget(self.btn_copy_pytest_logic)

        self.btn_export_logic_html = QPushButton("💾 Export HTML")
        self.btn_export_logic_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 700;")
        self.btn_export_logic_html.clicked.connect(self._export_logic_html)
        top_row.addWidget(self.btn_export_logic_html)

        self.btn_rerun_logic = QPushButton("🔄 Re-run")
        self.btn_rerun_logic.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_rerun_logic.clicked.connect(self._rerun_logic_audit)
        top_row.addWidget(self.btn_rerun_logic)

        header_vbox.addLayout(top_row)

        self.logic_target_lbl = QLabel("Target: Awaiting Execution | Audit: Multi-step checkout flows, state skipping, parameter tampering, concurrency double-spend, and MFA bypass")
        self.logic_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.logic_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.logic_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Metric Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)
        self.card_logic_score = self._create_metric_card("LOGIC SCORE", "--", "#00ff9d")
        self.card_logic_status = self._create_metric_card("INTEGRITY STATUS", "--", "#a855f7")
        self.card_logic_workflows = self._create_metric_card("WORKFLOWS AUDITED", "0", "#38bdf8")
        self.card_logic_checks = self._create_metric_card("TESTED TRANSITIONS", "0", "#ffb800")
        self.card_logic_defects = self._create_metric_card("LOGIC DEFECTS", "0", "#ff2a44")
        self.card_logic_warnings = self._create_metric_card("WARNINGS", "0", "#f97316")

        stats_layout.addWidget(self.card_logic_score)
        stats_layout.addWidget(self.card_logic_status)
        stats_layout.addWidget(self.card_logic_workflows)
        stats_layout.addWidget(self.card_logic_checks)
        stats_layout.addWidget(self.card_logic_defects)
        stats_layout.addWidget(self.card_logic_warnings)
        layout.addLayout(stats_layout)

        # Filter bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(5)
        self.btn_fltr_logic_all = QPushButton("All")
        self.btn_fltr_logic_price = QPushButton("Price/Qty")
        self.btn_fltr_logic_sequence = QPushButton("State Machine")
        self.btn_fltr_logic_privilege = QPushButton("Privilege")
        self.btn_fltr_logic_concurrency = QPushButton("Concurrency")
        self.btn_fltr_logic_mfa = QPushButton("MFA")
        self.btn_fltr_logic_defects = QPushButton("Defects Only")

        for btn in (
            self.btn_fltr_logic_all,
            self.btn_fltr_logic_price,
            self.btn_fltr_logic_sequence,
            self.btn_fltr_logic_privilege,
            self.btn_fltr_logic_concurrency,
            self.btn_fltr_logic_mfa,
            self.btn_fltr_logic_defects,
        ):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 4px 9px; font-size: 11px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_logic_all.clicked.connect(lambda: self._filter_logic_defects("all"))
        self.btn_fltr_logic_price.clicked.connect(lambda: self._filter_logic_defects("price"))
        self.btn_fltr_logic_sequence.clicked.connect(lambda: self._filter_logic_defects("sequence"))
        self.btn_fltr_logic_privilege.clicked.connect(lambda: self._filter_logic_defects("privilege"))
        self.btn_fltr_logic_concurrency.clicked.connect(lambda: self._filter_logic_defects("concurrency"))
        self.btn_fltr_logic_mfa.clicked.connect(lambda: self._filter_logic_defects("mfa"))
        self.btn_fltr_logic_defects.clicked.connect(lambda: self._filter_logic_defects("defects_only"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Telemetry & Workflows / Defects, Right Tabs
        splitter = QSplitter(Qt.Horizontal)

        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        # 1. Evaluated Business Workflows Table
        wf_title = QLabel("🔄 Evaluated Business Workflows & State Invariants")
        wf_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #a855f7;")
        left_layout.addWidget(wf_title)

        self.logic_workflows_table = QTableWidget()
        self.logic_workflows_table.setColumnCount(1)
        self.logic_workflows_table.setHorizontalHeaderLabels(["Flow & State Sequence"])
        self.logic_workflows_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.logic_workflows_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logic_workflows_table.setFixedHeight(120)
        left_layout.addWidget(self.logic_workflows_table)

        # 2. Defect Matrix
        defects_title = QLabel("🔎 Business Logic Flaw & Parameter Tampering Matrix")
        defects_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #ffb800;")
        left_layout.addWidget(defects_title)

        self.logic_defects_table = QTableWidget()
        self.logic_defects_table.setColumnCount(6)
        self.logic_defects_table.setHorizontalHeaderLabels(["ID", "Category", "Severity", "Status", "Title", "Workflow"])
        self.logic_defects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.logic_defects_table.setColumnWidth(0, 80)
        self.logic_defects_table.setColumnWidth(1, 90)
        self.logic_defects_table.setColumnWidth(2, 65)
        self.logic_defects_table.setColumnWidth(3, 65)
        self.logic_defects_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.logic_defects_table.setColumnWidth(5, 95)
        self.logic_defects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.logic_defects_table.setSelectionMode(QTableWidget.SingleSelection)
        self.logic_defects_table.itemSelectionChanged.connect(self._on_logic_defect_selected)
        left_layout.addWidget(self.logic_defects_table)

        splitter.addWidget(left_box)

        # Right Column: 3 Tabs
        self.logic_tabs = QTabWidget()
        self.logic_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 5px 8px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #a855f7;
                border-bottom: 2px solid #a855f7;
            }
        """)

        # Tab 0: 🔎 Defect Inspector inside QScrollArea to prevent content squishing
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_scroll.setFrameShape(QFrame.NoFrame)
        insp_scroll.setStyleSheet("background: transparent; border: none;")

        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(12, 10, 12, 10)
        insp_layout.setSpacing(7)

        self.logic_insp_title = QLabel("Select a business logic check to inspect sequence flaw.")
        self.logic_insp_title.setStyleSheet("font-size: 13.5px; font-weight: 800; color: #a855f7;")
        self.logic_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.logic_insp_title)

        self.logic_insp_meta = QLabel("Workflow: -- | Category: --")
        self.logic_insp_meta.setStyleSheet("font-size: 11.5px; color: #a855f7; font-weight: 700;")
        insp_layout.addWidget(self.logic_insp_meta)

        self.logic_insp_desc = QLabel("Description: --")
        self.logic_insp_desc.setStyleSheet("font-size: 11.5px; color: #cbd5e1; line-height: 1.3;")
        self.logic_insp_desc.setWordWrap(True)
        insp_layout.addWidget(self.logic_insp_desc)

        self.logic_insp_impact = QLabel("Impact: --")
        self.logic_insp_impact.setStyleSheet("font-size: 11.5px; color: #fca5a5; line-height: 1.3;")
        self.logic_insp_impact.setWordWrap(True)
        insp_layout.addWidget(self.logic_insp_impact)

        poc_lbl = QLabel("Flawed Sequence Proof of Concept (PoC) / Exploit Payload:")
        poc_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #ff3366;")
        insp_layout.addWidget(poc_lbl)

        self.logic_insp_poc = QTextEdit()
        self.logic_insp_poc.setReadOnly(True)
        self.logic_insp_poc.setStyleSheet("background: #090c13; color: #f43f5e; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.logic_insp_poc.setMinimumHeight(90)
        self.logic_insp_poc.setMaximumHeight(160)
        insp_layout.addWidget(self.logic_insp_poc)

        remed_lbl = QLabel("Remediation Pattern & Server-Side State Invariant:")
        remed_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #00ff9d;")
        insp_layout.addWidget(remed_lbl)

        self.logic_insp_remed = QTextEdit()
        self.logic_insp_remed.setReadOnly(True)
        self.logic_insp_remed.setStyleSheet("background: #090c13; color: #a7f3d0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.logic_insp_remed.setMinimumHeight(90)
        self.logic_insp_remed.setMaximumHeight(180)
        insp_layout.addWidget(self.logic_insp_remed)

        # Live PoC Simulation & Auto-Patcher Integration
        logic_act_box = QHBoxLayout()
        logic_act_box.setSpacing(8)
        self.btn_logic_live_poc = QPushButton("▶ Live PoC Simulation")
        self.btn_logic_live_poc.setStyleSheet("background-color: #ff2a44; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_logic_live_poc.clicked.connect(self._run_live_poc_for_logic)
        logic_act_box.addWidget(self.btn_logic_live_poc)

        self.btn_logic_autopatch = QPushButton("✨ Auto-Patcher (.patch)")
        self.btn_logic_autopatch.setStyleSheet("background-color: #00ff9d; color: #0b0f19; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_logic_autopatch.clicked.connect(self._show_patch_modal_for_logic)
        logic_act_box.addWidget(self.btn_logic_autopatch)
        insp_layout.addLayout(logic_act_box)

        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t_insp_layout = QVBoxLayout(tab_insp)
        t_insp_layout.setContentsMargins(0, 0, 0, 0)
        t_insp_layout.addWidget(insp_scroll)
        self.logic_tabs.addTab(tab_insp, "🔎 Inspector")

        # Tab 1: ⚡ Pytest Test Suite
        tab_py = QWidget()
        py_layout = QVBoxLayout(tab_py)
        py_layout.setContentsMargins(12, 10, 12, 10)
        py_layout.setSpacing(6)

        py_top = QHBoxLayout()
        py_title = QLabel("Automated Pytest Suite (test_business_logic.py)")
        py_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #059669;")
        py_top.addWidget(py_title)
        py_top.addStretch()

        self.btn_copy_logic_pytest_tab = QPushButton("⚡ Copy Suite")
        self.btn_copy_logic_pytest_tab.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 4px 11px; font-size: 11px;")
        self.btn_copy_logic_pytest_tab.clicked.connect(self._copy_pytest_logic)
        py_top.addWidget(self.btn_copy_logic_pytest_tab)
        py_layout.addLayout(py_top)

        self.logic_pytest_txt = QTextEdit()
        self.logic_pytest_txt.setReadOnly(True)
        self.logic_pytest_txt.setStyleSheet("background: #090c13; color: #86efac; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        py_layout.addWidget(self.logic_pytest_txt)
        self.logic_tabs.addTab(tab_py, "⚡ Pytest")

        # Tab 2: 📋 Client Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(12, 10, 12, 10)
        deliv_layout.setSpacing(6)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Executive Business Logic Deliverable (Markdown)")
        deliv_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #a855f7;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_logic_deliv = QPushButton("📋 Copy Deliverable")
        self.btn_copy_logic_deliv.setStyleSheet("background-color: #7c3aed; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 4px 11px; font-size: 11px;")
        self.btn_copy_logic_deliv.clicked.connect(self._copy_logic_markdown)
        deliv_top.addWidget(self.btn_copy_logic_deliv)
        deliv_layout.addLayout(deliv_top)

        self.logic_deliverable_txt = QTextEdit()
        self.logic_deliverable_txt.setReadOnly(True)
        self.logic_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.logic_deliverable_txt)
        self.logic_tabs.addTab(tab_deliv, "📋 Deliverable")

        splitter.addWidget(self.logic_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    def _setup_memory_page(self):
        layout = QVBoxLayout(self.page_memory)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header bar
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        h_title = QLabel("🧠 Memory Leak & Resource Profiler Workbench")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #a855f7;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        self.btn_copy_mem_markdown = QPushButton("📋 Copy Report")
        self.btn_copy_mem_markdown.setStyleSheet("background-color: #7c3aed; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_mem_markdown.clicked.connect(self._copy_mem_markdown)
        top_row.addWidget(self.btn_copy_mem_markdown)

        self.btn_copy_leak_script = QPushButton("⚡ Diagnostic Script")
        self.btn_copy_leak_script.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_leak_script.clicked.connect(self._copy_leak_script)
        top_row.addWidget(self.btn_copy_leak_script)

        self.btn_export_mem_html = QPushButton("💾 Export HTML")
        self.btn_export_mem_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 700;")
        self.btn_export_mem_html.clicked.connect(self._export_mem_html)
        top_row.addWidget(self.btn_export_mem_html)

        self.btn_rerun_mem = QPushButton("🔄 Re-run")
        self.btn_rerun_mem.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_rerun_mem.clicked.connect(self._rerun_mem_audit)
        top_row.addWidget(self.btn_rerun_mem)

        header_vbox.addLayout(top_row)

        self.mem_target_lbl = QLabel("Target: Awaiting Execution | Audit: Private working set, OS kernel handles, GDI object limits, and detached DOM/Context references")
        self.mem_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.mem_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.mem_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Metric Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)
        self.card_mem_score = self._create_metric_card("MEMORY SCORE", "--", "#00ff9d")
        self.card_mem_status = self._create_metric_card("STABILITY STATUS", "--", "#a855f7")
        self.card_mem_peak = self._create_metric_card("PEAK WORKING SET", "--", "#ffb800")
        self.card_mem_delta = self._create_metric_card("NET RAM DRIFT", "--", "#ff2a44")
        self.card_mem_handles = self._create_metric_card("PEAK HANDLES", "0", "#38bdf8")
        self.card_mem_defects = self._create_metric_card("MEMORY DEFECTS", "0", "#f97316")

        stats_layout.addWidget(self.card_mem_score)
        stats_layout.addWidget(self.card_mem_status)
        stats_layout.addWidget(self.card_mem_peak)
        stats_layout.addWidget(self.card_mem_delta)
        stats_layout.addWidget(self.card_mem_handles)
        stats_layout.addWidget(self.card_mem_defects)
        layout.addLayout(stats_layout)

        # Filter bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(5)
        self.btn_fltr_mem_all = QPushButton("All")
        self.btn_fltr_mem_heap = QPushButton("Heap & RAM")
        self.btn_fltr_mem_handles = QPushButton("OS Handles")
        self.btn_fltr_mem_gdi = QPushButton("GDI Objects")
        self.btn_fltr_mem_detached = QPushButton("Detached Nodes")
        self.btn_fltr_mem_defects = QPushButton("Defects Only")

        for btn in (
            self.btn_fltr_mem_all,
            self.btn_fltr_mem_heap,
            self.btn_fltr_mem_handles,
            self.btn_fltr_mem_gdi,
            self.btn_fltr_mem_detached,
            self.btn_fltr_mem_defects,
        ):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 4px 9px; font-size: 11px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_mem_all.clicked.connect(lambda: self._filter_mem_defects("all"))
        self.btn_fltr_mem_heap.clicked.connect(lambda: self._filter_mem_defects("heap"))
        self.btn_fltr_mem_handles.clicked.connect(lambda: self._filter_mem_defects("handles"))
        self.btn_fltr_mem_gdi.clicked.connect(lambda: self._filter_mem_defects("gdi"))
        self.btn_fltr_mem_detached.clicked.connect(lambda: self._filter_mem_defects("detached"))
        self.btn_fltr_mem_defects.clicked.connect(lambda: self._filter_mem_defects("defects_only"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Telemetry & Defects, Right Tabs
        splitter = QSplitter(Qt.Horizontal)

        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        # 1. Telemetry Table
        tel_title = QLabel("📊 Process Working Set & Resource Runaway Telemetry")
        tel_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #38bdf8;")
        left_layout.addWidget(tel_title)

        self.mem_telemetry_table = QTableWidget()
        self.mem_telemetry_table.setColumnCount(2)
        self.mem_telemetry_table.setHorizontalHeaderLabels(["Resource Attribute", "Profiled Value"])
        self.mem_telemetry_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.mem_telemetry_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.mem_telemetry_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.mem_telemetry_table.setFixedHeight(120)
        left_layout.addWidget(self.mem_telemetry_table)

        # 2. Defect Matrix
        defects_title = QLabel("🔎 Memory & Handle Exhaustion Defect Matrix")
        defects_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #ffb800;")
        left_layout.addWidget(defects_title)

        self.mem_defects_table = QTableWidget()
        self.mem_defects_table.setColumnCount(6)
        self.mem_defects_table.setHorizontalHeaderLabels(["ID", "Category", "Severity", "Status", "Title", "Component"])
        self.mem_defects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.mem_defects_table.setColumnWidth(0, 80)
        self.mem_defects_table.setColumnWidth(1, 90)
        self.mem_defects_table.setColumnWidth(2, 65)
        self.mem_defects_table.setColumnWidth(3, 65)
        self.mem_defects_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.mem_defects_table.setColumnWidth(5, 95)
        self.mem_defects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.mem_defects_table.setSelectionMode(QTableWidget.SingleSelection)
        self.mem_defects_table.itemSelectionChanged.connect(self._on_mem_defect_selected)
        left_layout.addWidget(self.mem_defects_table)

        splitter.addWidget(left_box)

        # Right Column: 3 Tabs
        self.mem_tabs = QTabWidget()
        self.mem_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 5px 8px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #a855f7;
                border-bottom: 2px solid #a855f7;
            }
        """)

        # Tab 0: 🔎 Defect Inspector & Trace wrapped in QScrollArea
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_scroll.setFrameShape(QFrame.NoFrame)
        insp_scroll.setStyleSheet("background: transparent; border: none;")

        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(12, 10, 12, 10)
        insp_layout.setSpacing(7)

        self.mem_insp_title = QLabel("Select a memory check to inspect leak trace.")
        self.mem_insp_title.setStyleSheet("font-size: 13.5px; font-weight: 800; color: #a855f7;")
        self.mem_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.mem_insp_title)

        self.mem_insp_meta = QLabel("Component: -- | Category: -- | Leak Rate: --")
        self.mem_insp_meta.setStyleSheet("font-size: 11.5px; color: #a855f7; font-weight: 700;")
        insp_layout.addWidget(self.mem_insp_meta)

        self.mem_insp_desc = QLabel("Description: --")
        self.mem_insp_desc.setStyleSheet("font-size: 11.5px; color: #cbd5e1; line-height: 1.3;")
        self.mem_insp_desc.setWordWrap(True)
        insp_layout.addWidget(self.mem_insp_desc)

        self.mem_insp_impact = QLabel("Impact: --")
        self.mem_insp_impact.setStyleSheet("font-size: 11.5px; color: #fca5a5; line-height: 1.3;")
        self.mem_insp_impact.setWordWrap(True)
        insp_layout.addWidget(self.mem_insp_impact)

        poc_lbl = QLabel("Diagnostic Test Scenario / Leak Trace PoC:")
        poc_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #ff3366;")
        insp_layout.addWidget(poc_lbl)

        self.mem_insp_poc = QTextEdit()
        self.mem_insp_poc.setReadOnly(True)
        self.mem_insp_poc.setStyleSheet("background: #090c13; color: #f43f5e; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.mem_insp_poc.setMinimumHeight(90)
        self.mem_insp_poc.setMaximumHeight(160)
        insp_layout.addWidget(self.mem_insp_poc)

        remed_lbl = QLabel("RAII / Lifecycle Remediation Pattern:")
        remed_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #00ff9d;")
        insp_layout.addWidget(remed_lbl)

        self.mem_insp_remed = QTextEdit()
        self.mem_insp_remed.setReadOnly(True)
        self.mem_insp_remed.setStyleSheet("background: #090c13; color: #a7f3d0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.mem_insp_remed.setMinimumHeight(90)
        self.mem_insp_remed.setMaximumHeight(180)
        insp_layout.addWidget(self.mem_insp_remed)
        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t_insp_layout = QVBoxLayout(tab_insp)
        t_insp_layout.setContentsMargins(0, 0, 0, 0)
        t_insp_layout.addWidget(insp_scroll)
        self.mem_tabs.addTab(tab_insp, "🔎 Inspector")

        # Tab 1: ⚡ Diagnostic Stress Script
        tab_script = QWidget()
        sc_layout = QVBoxLayout(tab_script)
        sc_layout.setContentsMargins(12, 10, 12, 10)
        sc_layout.setSpacing(6)

        sc_top = QHBoxLayout()
        sc_title = QLabel("Automated Memory & Handle Stress Profiler Script")
        sc_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #059669;")
        sc_top.addWidget(sc_title)
        sc_top.addStretch()

        self.btn_copy_leak_script_tab = QPushButton("⚡ Copy Script")
        self.btn_copy_leak_script_tab.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_leak_script_tab.clicked.connect(self._copy_leak_script)
        sc_top.addWidget(self.btn_copy_leak_script_tab)
        sc_layout.addLayout(sc_top)

        self.mem_script_txt = QTextEdit()
        self.mem_script_txt.setReadOnly(True)
        self.mem_script_txt.setStyleSheet("background: #090c13; color: #86efac; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        sc_layout.addWidget(self.mem_script_txt)
        self.mem_tabs.addTab(tab_script, "⚡ Diagnostics")

        # Tab 2: 📋 Client Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(14, 12, 14, 12)
        deliv_layout.setSpacing(8)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Copiable Executive Memory & Resource Deliverable (Markdown)")
        deliv_title.setStyleSheet("font-size: 12px; font-weight: 800; color: #a855f7;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_mem_deliv = QPushButton("📋 Copy Full Report")
        self.btn_copy_mem_deliv.setStyleSheet("background-color: #7c3aed; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 6px 14px; font-size: 11.5px;")
        self.btn_copy_mem_deliv.clicked.connect(self._copy_mem_markdown)
        deliv_top.addWidget(self.btn_copy_mem_deliv)
        deliv_layout.addLayout(deliv_top)

        self.mem_deliverable_txt = QTextEdit()
        self.mem_deliverable_txt.setReadOnly(True)
        self.mem_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11.5px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.mem_deliverable_txt)
        self.mem_tabs.addTab(tab_deliv, "📋 Deliverable")

        splitter.addWidget(self.mem_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    def _setup_a11y_page(self):
        layout = QVBoxLayout(self.page_a11y)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header bar
        header_vbox = QVBoxLayout()
        header_vbox.setSpacing(6)

        top_row = QHBoxLayout()
        top_row.setSpacing(8)

        h_title = QLabel("♿ Accessibility & VPAT Conformance Workbench")
        h_title.setStyleSheet("font-size: 15px; font-weight: 800; color: #38bdf8;")
        top_row.addWidget(h_title)
        top_row.addStretch()

        self.btn_copy_vpat_markdown = QPushButton("📋 Copy VPAT")
        self.btn_copy_vpat_markdown.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_vpat_markdown.clicked.connect(self._copy_vpat_markdown)
        top_row.addWidget(self.btn_copy_vpat_markdown)

        self.btn_copy_axe_script = QPushButton("⚡ Axe-Core Suite")
        self.btn_copy_axe_script.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_copy_axe_script.clicked.connect(self._copy_axe_script)
        top_row.addWidget(self.btn_copy_axe_script)

        self.btn_export_a11y_html = QPushButton("💾 Export HTML")
        self.btn_export_a11y_html.setStyleSheet("background-color: #1a2333; color: #cbd5e1; border: 1px solid #2a3b53; border-radius: 6px; padding: 5px 11px; font-size: 11px; font-weight: 700;")
        self.btn_export_a11y_html.clicked.connect(self._export_a11y_html)
        top_row.addWidget(self.btn_export_a11y_html)

        self.btn_rerun_a11y = QPushButton("🔄 Re-run")
        self.btn_rerun_a11y.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 5px 11px; font-size: 11px;")
        self.btn_rerun_a11y.clicked.connect(self._rerun_a11y_audit)
        top_row.addWidget(self.btn_rerun_a11y)

        header_vbox.addLayout(top_row)

        self.a11y_target_lbl = QLabel("Target: Awaiting Execution | Audit: W3C WCAG 2.2 (Level A/AA/AAA), Section 508, Screen Reader ARIA Tree, and VPAT 2.4")
        self.a11y_target_lbl.setStyleSheet("font-size: 11.5px; color: #8b93a4; font-weight: 500;")
        self.a11y_target_lbl.setWordWrap(True)
        header_vbox.addWidget(self.a11y_target_lbl)

        layout.addLayout(header_vbox)

        # 6 KPI Metric Cards
        stats_layout = QHBoxLayout()
        stats_layout.setSpacing(8)
        self.card_a11y_score = self._create_metric_card("WCAG SCORE", "--", "#00ff9d")
        self.card_a11y_status = self._create_metric_card("CONFORMANCE STATUS", "--", "#38bdf8")
        self.card_a11y_checked = self._create_metric_card("CRITERIA CHECKED", "0", "#a855f7")
        self.card_a11y_passed = self._create_metric_card("CONFORMING CRITERIA", "0", "#00ff9d")
        self.card_a11y_defects = self._create_metric_card("A11Y DEFECTS", "0", "#ff2a44")
        self.card_a11y_contrast = self._create_metric_card("CONTRAST DEFECTS", "0", "#ffb800")

        stats_layout.addWidget(self.card_a11y_score)
        stats_layout.addWidget(self.card_a11y_status)
        stats_layout.addWidget(self.card_a11y_checked)
        stats_layout.addWidget(self.card_a11y_passed)
        stats_layout.addWidget(self.card_a11y_defects)
        stats_layout.addWidget(self.card_a11y_contrast)
        layout.addLayout(stats_layout)

        # Filter bar
        fltr_row = QHBoxLayout()
        fltr_row.setSpacing(5)
        self.btn_fltr_a11y_all = QPushButton("All")
        self.btn_fltr_a11y_perceivable = QPushButton("Perceivable")
        self.btn_fltr_a11y_operable = QPushButton("Operable")
        self.btn_fltr_a11y_understandable = QPushButton("Understandable")
        self.btn_fltr_a11y_robust = QPushButton("Robust")
        self.btn_fltr_a11y_defects = QPushButton("Defects Only")

        for btn in (
            self.btn_fltr_a11y_all,
            self.btn_fltr_a11y_perceivable,
            self.btn_fltr_a11y_operable,
            self.btn_fltr_a11y_understandable,
            self.btn_fltr_a11y_robust,
            self.btn_fltr_a11y_defects,
        ):
            btn.setStyleSheet("background-color: #12151d; color: #cbd5e1; border: 1px solid #1e2434; border-radius: 6px; padding: 4px 9px; font-size: 11px;")
            fltr_row.addWidget(btn)

        self.btn_fltr_a11y_all.clicked.connect(lambda: self._filter_a11y_defects("all"))
        self.btn_fltr_a11y_perceivable.clicked.connect(lambda: self._filter_a11y_defects("perceivable"))
        self.btn_fltr_a11y_operable.clicked.connect(lambda: self._filter_a11y_defects("operable"))
        self.btn_fltr_a11y_understandable.clicked.connect(lambda: self._filter_a11y_defects("understandable"))
        self.btn_fltr_a11y_robust.clicked.connect(lambda: self._filter_a11y_defects("robust"))
        self.btn_fltr_a11y_defects.clicked.connect(lambda: self._filter_a11y_defects("defects_only"))
        fltr_row.addStretch()
        layout.addLayout(fltr_row)

        # Splitter: Left Telemetry & Defects, Right Tabs
        splitter = QSplitter(Qt.Horizontal)

        left_box = QWidget()
        left_layout = QVBoxLayout(left_box)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(6)

        # 1. ARIA Landmarks Table
        tel_title = QLabel("🌐 WAI-ARIA Screen Reader Tree & Semantic Landmarks")
        tel_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #38bdf8;")
        left_layout.addWidget(tel_title)

        self.a11y_landmarks_table = QTableWidget()
        self.a11y_landmarks_table.setColumnCount(4)
        self.a11y_landmarks_table.setHorizontalHeaderLabels(["Role", "Element", "Accessible Target", "Status"])
        self.a11y_landmarks_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.a11y_landmarks_table.setColumnWidth(0, 85)
        self.a11y_landmarks_table.setColumnWidth(1, 75)
        self.a11y_landmarks_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.a11y_landmarks_table.setColumnWidth(3, 70)
        self.a11y_landmarks_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.a11y_landmarks_table.setFixedHeight(120)
        left_layout.addWidget(self.a11y_landmarks_table)

        # 2. Defect Matrix
        defects_title = QLabel("🔎 WCAG 2.2 Level A & AA Criteria Defect Matrix")
        defects_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #ffb800;")
        left_layout.addWidget(defects_title)

        self.a11y_defects_table = QTableWidget()
        self.a11y_defects_table.setColumnCount(6)
        self.a11y_defects_table.setHorizontalHeaderLabels(["ID", "WCAG SC", "Level", "Status", "Finding Title", "VPAT Conformance"])
        self.a11y_defects_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.a11y_defects_table.setColumnWidth(0, 80)
        self.a11y_defects_table.setColumnWidth(1, 75)
        self.a11y_defects_table.setColumnWidth(2, 60)
        self.a11y_defects_table.setColumnWidth(3, 65)
        self.a11y_defects_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.a11y_defects_table.setColumnWidth(5, 95)
        self.a11y_defects_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.a11y_defects_table.setSelectionMode(QTableWidget.SingleSelection)
        self.a11y_defects_table.itemSelectionChanged.connect(self._on_a11y_defect_selected)
        left_layout.addWidget(self.a11y_defects_table)

        splitter.addWidget(left_box)

        # Right Column: 3 Tabs
        self.a11y_tabs = QTabWidget()
        self.a11y_tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e2434;
                background-color: #0e121b;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #121622;
                color: #8b9bb4;
                padding: 5px 8px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 2px;
                font-weight: 700;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background: #1a2233;
                color: #38bdf8;
                border-bottom: 2px solid #38bdf8;
            }
        """)

        # Tab 0: 🔎 Defect Inspector & Remediation wrapped in QScrollArea
        tab_insp = QWidget()
        insp_scroll = QScrollArea()
        insp_scroll.setWidgetResizable(True)
        insp_scroll.setFrameShape(QFrame.NoFrame)
        insp_scroll.setStyleSheet("background: transparent; border: none;")

        insp_content = QWidget()
        insp_layout = QVBoxLayout(insp_content)
        insp_layout.setContentsMargins(12, 10, 12, 10)
        insp_layout.setSpacing(7)

        self.a11y_insp_title = QLabel("Select an accessibility criterion to inspect remediation.")
        self.a11y_insp_title.setStyleSheet("font-size: 13.5px; font-weight: 800; color: #38bdf8;")
        self.a11y_insp_title.setWordWrap(True)
        insp_layout.addWidget(self.a11y_insp_title)

        self.a11y_insp_meta = QLabel("WCAG SC: -- | Principle: -- | Level: --")
        self.a11y_insp_meta.setStyleSheet("font-size: 11.5px; color: #38bdf8; font-weight: 700;")
        insp_layout.addWidget(self.a11y_insp_meta)

        self.a11y_insp_desc = QLabel("Description: --")
        self.a11y_insp_desc.setStyleSheet("font-size: 11.5px; color: #cbd5e1; line-height: 1.3;")
        self.a11y_insp_desc.setWordWrap(True)
        insp_layout.addWidget(self.a11y_insp_desc)

        self.a11y_insp_impact = QLabel("Impact: --")
        self.a11y_insp_impact.setStyleSheet("font-size: 11.5px; color: #fca5a5; line-height: 1.3;")
        self.a11y_insp_impact.setWordWrap(True)
        insp_layout.addWidget(self.a11y_insp_impact)

        remed_lbl = QLabel("Accessible Code Remediation Pattern (HTML / CSS / WAI-ARIA):")
        remed_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #00ff9d;")
        insp_layout.addWidget(remed_lbl)

        self.a11y_insp_code = QTextEdit()
        self.a11y_insp_code.setReadOnly(True)
        self.a11y_insp_code.setStyleSheet("background: #090c13; color: #a7f3d0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        self.a11y_insp_code.setMinimumHeight(120)
        self.a11y_insp_code.setMaximumHeight(220)
        insp_layout.addWidget(self.a11y_insp_code)
        insp_layout.addStretch()

        insp_scroll.setWidget(insp_content)
        t_insp_layout = QVBoxLayout(tab_insp)
        t_insp_layout.setContentsMargins(0, 0, 0, 0)
        t_insp_layout.addWidget(insp_scroll)
        self.a11y_tabs.addTab(tab_insp, "🔎 Inspector")

        # Tab 1: ⚡ Axe-Core / Playwright Test Suite
        tab_axe = QWidget()
        axe_layout = QVBoxLayout(tab_axe)
        axe_layout.setContentsMargins(12, 10, 12, 10)
        axe_layout.setSpacing(6)

        axe_top = QHBoxLayout()
        axe_title = QLabel("Automated Axe-Core & Playwright Test Suite (test_accessibility_wcag.py)")
        axe_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #059669;")
        axe_top.addWidget(axe_title)
        axe_top.addStretch()

        self.btn_copy_axe_tab = QPushButton("⚡ Copy Test Suite")
        self.btn_copy_axe_tab.setStyleSheet("background-color: #059669; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 4px 11px; font-size: 11px;")
        self.btn_copy_axe_tab.clicked.connect(self._copy_axe_script)
        axe_top.addWidget(self.btn_copy_axe_tab)
        axe_layout.addLayout(axe_top)

        self.a11y_axe_txt = QTextEdit()
        self.a11y_axe_txt.setReadOnly(True)
        self.a11y_axe_txt.setStyleSheet("background: #090c13; color: #86efac; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        axe_layout.addWidget(self.a11y_axe_txt)
        self.a11y_tabs.addTab(tab_axe, "⚡ Axe-Core")

        # Tab 2: 📋 Official VPAT Deliverable
        tab_deliv = QWidget()
        deliv_layout = QVBoxLayout(tab_deliv)
        deliv_layout.setContentsMargins(12, 10, 12, 10)
        deliv_layout.setSpacing(6)

        deliv_top = QHBoxLayout()
        deliv_title = QLabel("Official VPAT 2.4 / Section 508 Deliverable (Markdown)")
        deliv_title.setStyleSheet("font-size: 11.5px; font-weight: 800; color: #38bdf8;")
        deliv_top.addWidget(deliv_title)
        deliv_top.addStretch()

        self.btn_copy_vpat_deliv = QPushButton("📋 Copy Full VPAT")
        self.btn_copy_vpat_deliv.setStyleSheet("background-color: #0284c7; color: #ffffff; font-weight: 800; border: none; border-radius: 6px; padding: 4px 11px; font-size: 11px;")
        self.btn_copy_vpat_deliv.clicked.connect(self._copy_vpat_markdown)
        deliv_top.addWidget(self.btn_copy_vpat_deliv)
        deliv_layout.addLayout(deliv_top)

        self.a11y_deliverable_txt = QTextEdit()
        self.a11y_deliverable_txt.setReadOnly(True)
        self.a11y_deliverable_txt.setStyleSheet("background: #090c13; color: #f1f5f9; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px; border: 1px solid #1a2233; border-radius: 6px;")
        deliv_layout.addWidget(self.a11y_deliverable_txt)
        self.a11y_tabs.addTab(tab_deliv, "📋 VPAT Report")

        splitter.addWidget(self.a11y_tabs)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 5)
        layout.addWidget(splitter)

    # =========================================================================
    # SCAN EXECUTION LOGIC
    # =========================================================================
    def _start_scan(self, bugs_only: bool = False, open_attacks: bool = False, open_qa: bool = False, open_api: bool = False, open_a11y: bool = False, open_logic: bool = False):
        target_str = self.target_path_edit.text().strip()
        if not target_str:
            QMessageBox.warning(self, "Missing Target", "Please select a target APK/EXE file or enter a valid website URL.")
            return

        self._requested_attack_tab = open_attacks
        self._requested_bug_tab = bugs_only
        self._requested_qa_tab = open_qa
        self._requested_api_tab = open_api
        self._requested_a11y_tab = open_a11y
        self._requested_logic_tab = open_logic

        target_type = self._selected_target_type
        raw_level = self.level_combo.currentData()
        level = ScanLevel.from_string(raw_level)

        type_str = target_type.value if hasattr(target_type, "value") else str(target_type)
        if open_a11y:
            scan_label = "ACCESSIBILITY & VPAT AUDIT"
        elif open_logic:
            scan_label = "BUSINESS LOGIC AUDIT"
        elif open_api:
            scan_label = "REST & BACKEND API AUDIT"
        elif open_qa:
            scan_label = "QA TEST AUTOMATION AUDIT"
        elif open_attacks:
            scan_label = "ATTACK RESILIENCE AUDIT"
        elif bugs_only:
            scan_label = "BUG AUDIT"
        else:
            scan_label = "SECURITY & DEFECT SCAN"

        # Switch to Progress tab (index 1)
        self._switch_page(1)
        self.log_console.clear()
        self.progress_bar.setValue(0)
        self.scan_headline.setText(f"{scan_label}: {os.path.basename(target_str)} ({type_str.upper()})")
        self.start_btn.setEnabled(False)
        self.start_bug_btn.setEnabled(False)
        self.start_atk_btn.setEnabled(False)
        if hasattr(self, "start_qa_btn"):
            self.start_qa_btn.setEnabled(False)
        if hasattr(self, "start_a11y_btn"):
            self.start_a11y_btn.setEnabled(False)

        # Update right telemetry
        self.box_active_scans.v_lbl.setText("1")
        self.ss_dot_lbl.setText("● Audit in Progress...")
        self.ss_dot_lbl.setStyleSheet("font-size: 11px; color: #00d4ff; font-weight: 700;")

        # Launch Worker Thread
        self.worker = ScanWorker(target_str, target_type, level, bugs_only=bugs_only)
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.log_signal.connect(self._on_log)
        self.worker.finished_signal.connect(self._on_scan_finished)
        self.worker.error_signal.connect(self._on_scan_error)
        self.worker.start()

    def _cancel_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.terminate()
            self.scan_headline.setText("SCAN CANCELLED BY USER")
            self.log_console.append("[ABORT] Scan terminated by user.")
            self.start_btn.setEnabled(True)
            self.start_bug_btn.setEnabled(True)
            self.start_atk_btn.setEnabled(True)
            if hasattr(self, "start_qa_btn"):
                self.start_qa_btn.setEnabled(True)
            if hasattr(self, "start_a11y_btn"):
                self.start_a11y_btn.setEnabled(True)
            self.box_active_scans.v_lbl.setText("0")
            self.ss_dot_lbl.setText("● All Systems Online")
            self.ss_dot_lbl.setStyleSheet("font-size: 11px; color: #ff2a44; font-weight: 700;")

    def _on_progress(self, pct: int, msg: str):
        self.progress_bar.setValue(pct)
        self.scan_headline.setText(msg)

    def _on_log(self, log_line: str):
        self.log_console.append(log_line)

    def _on_scan_error(self, err_msg: str):
        self.start_btn.setEnabled(True)
        self.start_bug_btn.setEnabled(True)
        self.start_atk_btn.setEnabled(True)
        if hasattr(self, "start_qa_btn"):
            self.start_qa_btn.setEnabled(True)
        if hasattr(self, "start_a11y_btn"):
            self.start_a11y_btn.setEnabled(True)
        self.box_active_scans.v_lbl.setText("0")
        self.ss_dot_lbl.setText("● All Systems Online")
        self.ss_dot_lbl.setStyleSheet("font-size: 11px; color: #ff2a44; font-weight: 700;")
        self.scan_headline.setText("SCAN FAILED")
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scan execution:\n{err_msg}")

    def _on_scan_finished(self, result: ScanResult):
        self.start_btn.setEnabled(True)
        self.start_bug_btn.setEnabled(True)
        self.start_atk_btn.setEnabled(True)
        if hasattr(self, "start_qa_btn"):
            self.start_qa_btn.setEnabled(True)
        if hasattr(self, "start_a11y_btn"):
            self.start_a11y_btn.setEnabled(True)
        self.current_result = result
        self.box_active_scans.v_lbl.setText("0")
        self.ss_dot_lbl.setText("● All Systems Online")
        self.ss_dot_lbl.setStyleSheet("font-size: 11px; color: #ff2a44; font-weight: 700;")

        # Save to database
        self.db.save_scan(result)
        self._load_history()

        # Update Right Telemetry
        self._update_right_telemetry_with_result(result)

        # Populate Views
        self._populate_threat_model(result)
        self._populate_findings(result)
        self._populate_bugs(result)
        self._populate_web_history(result)
        self._populate_attacks(result)
        self._populate_automation(result)
        self._populate_api(result)
        self._populate_perf(result)
        self._populate_cicd(result)
        self._populate_db(result)
        self._populate_compat(result)
        self._populate_network(result)
        self._populate_logic(result)
        self._populate_memory(result)
        self._populate_a11y(result)

        # Switch to requested tab
        if getattr(self, "_requested_a11y_tab", False):
            self._switch_page(17)  # Accessibility QA
            self._requested_a11y_tab = False
        elif getattr(self, "_requested_memory_tab", False):
            self._switch_page(16)  # Memory & Resource QA
            self._requested_memory_tab = False
        elif getattr(self, "_requested_logic_tab", False):
            self._switch_page(15)  # Business Logic QA
            self._requested_logic_tab = False
        elif getattr(self, "_requested_network_tab", False):
            self._switch_page(14)  # Network & TLS QA
            self._requested_network_tab = False
        elif getattr(self, "_requested_compat_tab", False):
            self._switch_page(13)  # Viewport & A11y QA
            self._requested_compat_tab = False
        elif getattr(self, "_requested_db_tab", False):
            self._switch_page(12)  # Database QA
            self._requested_db_tab = False
        elif getattr(self, "_requested_cicd_tab", False):
            self._switch_page(11)  # CI/CD Quality Gates
            self._requested_cicd_tab = False
        elif getattr(self, "_requested_perf_tab", False):
            self._switch_page(10)  # Concurrency / Load Testing
            self._requested_perf_tab = False
        elif getattr(self, "_requested_api_tab", False):
            self._switch_page(9)  # API Testing
            self._requested_api_tab = False
        elif getattr(self, "_requested_qa_tab", False):
            self._switch_page(8)  # QA Automation
            self._requested_qa_tab = False
        elif getattr(self, "_requested_attack_tab", False):
            self._switch_page(6)  # Test a Hack
            self._requested_attack_tab = False
        elif getattr(self, "_requested_bug_tab", False):
            self._switch_page(4)  # Bug Finder
            self._requested_bug_tab = False
        else:
            self._switch_page(2)  # Threat Analysis

    # =========================================================================
    # RIGHT TELEMETRY HELPERS
    # =========================================================================
    def _update_right_telemetry_defaults(self):
        self.metric_threats_lbl.setText("0 Threats")
        self.metric_vulns_lbl.setText("0 Vulns")
        self.metric_suspicious_lbl.setText("0 Defects")
        self.metric_score_lbl.setText("-- Score")

    def _update_right_telemetry_with_result(self, result: ScanResult):
        m = result.metrics
        threats = m.critical_count + m.high_count
        vulns = m.medium_count + m.low_count
        suspicious = m.total_bugs

        self.metric_threats_lbl.setText(f"{threats} Threats")
        self.metric_vulns_lbl.setText(f"{vulns} Vulns")
        self.metric_suspicious_lbl.setText(f"{suspicious} Defects")
        self.metric_score_lbl.setText(f"{int(m.security_score)} Score")

        tname = result.target.display_name if result.target else "Target"
        self.rc_badge.setText(f"Grade: {m.posture_grade}")
        self.recent_desc_lbl.setText(
            f"Last: {tname[:18]}\nScore: {m.security_score}/100 ({m.posture_grade})\n"
            f"Crit/High: {threats} | Bugs: {m.total_bugs}"
        )

    # =========================================================================
    # POPULATION LOGIC FOR INDIVIDUAL PAGES
    # =========================================================================
    def _populate_threat_model(self, result: ScanResult):
        model = ThreatModelGenerator.generate_threat_model(result)
        self.threat_narrative.setText(model["executive_summary"])

        while self.attacks_layout.count():
            item = self.attacks_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        header_lbl = QLabel(f"POTENTIAL ATTACK PATHS IDENTIFIED FOR THIS {model['target_type']}")
        header_lbl.setStyleSheet("font-size: 13px; font-weight: 800; color: #ff2a44; margin-bottom: 5px;")
        self.attacks_layout.addWidget(header_lbl)

        if model["plausible_attacks"]:
            for i, atk in enumerate(model["plausible_attacks"], start=1):
                card = QFrame()
                card.setStyleSheet("background-color: #12151d; border: 1px solid #1c2230; border-radius: 8px; padding: 12px; margin-bottom: 6px;")
                c_layout = QVBoxLayout(card)
                c_layout.setSpacing(6)

                top_row = QHBoxLayout()
                t_lbl = QLabel(f"{i}. {atk['name']}")
                t_lbl.setStyleSheet("font-size: 13.5px; font-weight: 700; color: #ffffff;")
                p_lbl = QLabel(atk["priority"])
                p_color = "#ff2a44" if "critical" in atk["priority"].lower() else "#ff6b22" if "high" in atk["priority"].lower() else "#ffb800"
                p_lbl.setStyleSheet(f"background-color: {p_color}; color: #000; font-size: 10px; font-weight: 800; padding: 2px 8px; border-radius: 4px;")
                top_row.addWidget(t_lbl)
                top_row.addStretch()
                top_row.addWidget(p_lbl)
                c_layout.addLayout(top_row)

                ref_lbl = QLabel(f"Triggered by: {atk['finding_ref']}")
                ref_lbl.setStyleSheet("font-size: 11px; color: #7b8497;")
                c_layout.addWidget(ref_lbl)

                sc_lbl = QLabel(atk["scenario"])
                sc_lbl.setWordWrap(True)
                sc_lbl.setStyleSheet("font-size: 12px; color: #cfdaf0;")
                c_layout.addWidget(sc_lbl)

                cav_lbl = QLabel(f"Important: {atk['caveat']}")
                cav_lbl.setWordWrap(True)
                cav_lbl.setStyleSheet("font-size: 11.5px; color: #ffdb80; background-color: #1b1712; padding: 6px; border-radius: 4px;")
                c_layout.addWidget(cav_lbl)

                self.attacks_layout.addWidget(card)
        else:
            clean_lbl = QLabel("Zero immediate high-probability exploitation attack paths identified.")
            clean_lbl.setStyleSheet("font-size: 12.5px; color: #00ff9d; font-style: italic;")
            self.attacks_layout.addWidget(clean_lbl)

        self.attacks_layout.addStretch()

    def _populate_findings(self, result: ScanResult):
        metrics = result.metrics
        self.card_grade.val_lbl.setText(metrics.posture_grade)
        self.card_score.val_lbl.setText(f"{metrics.security_score}")
        self.card_crit.val_lbl.setText(str(metrics.critical_count))
        self.card_high.val_lbl.setText(str(metrics.high_count))
        self.card_med.val_lbl.setText(str(metrics.medium_count))
        self.card_low.val_lbl.setText(str(metrics.low_count))
        self.card_pass.val_lbl.setText(str(metrics.passed))

        self.table.setRowCount(0)
        for i, f in enumerate(result.findings):
            self.table.insertRow(i)
            self.table.setItem(i, 0, QTableWidgetItem(f.check_id))

            sev_item = QTableWidgetItem(f.severity.value.upper())
            sev_item.setForeground(QColor(f.severity.badge_color))
            self.table.setItem(i, 1, sev_item)

            self.table.setItem(i, 2, QTableWidgetItem(f.title))
            self.table.setItem(i, 3, QTableWidgetItem(f.category))

            status_item = QTableWidgetItem(f.status.value.upper())
            if f.status == CheckStatus.PASSED:
                status_item.setForeground(QColor("#00ff9d"))
            elif f.status in (CheckStatus.FAILED, CheckStatus.WARNING):
                status_item.setForeground(QColor(f.severity.badge_color))
            self.table.setItem(i, 4, status_item)

        if result.findings:
            self.table.selectRow(0)

    def _apply_filter(self):
        if not self.current_result:
            return
        query = self.search_edit.text().lower()
        sev_filter = self.filter_combo.currentText()

        for row in range(self.table.rowCount()):
            cid = self.table.item(row, 0).text().lower()
            sev = self.table.item(row, 1).text().lower()
            title = self.table.item(row, 2).text().lower()
            cat = self.table.item(row, 3).text().lower()
            status = self.table.item(row, 4).text().lower()

            matches_query = query in cid or query in title or query in cat
            matches_sev = True
            if sev_filter == "Critical & High":
                matches_sev = sev in ("critical", "high") and status != "passed"
            elif sev_filter == "Medium & Low":
                matches_sev = sev in ("medium", "low") and status != "passed"
            elif sev_filter == "Passed Checks":
                matches_sev = status == "passed"

            self.table.setRowHidden(row, not (matches_query and matches_sev))

    def _on_finding_selected(self):
        if not self.current_result:
            return
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return
        row = selected_rows[0].row()
        cid = self.table.item(row, 0).text()

        match = next((f for f in self.current_result.findings if f.check_id == cid), None)
        if match:
            self.inspector_title.setText(match.title)
            self.inspector_meta.setText(
                f"Check ID: {match.check_id} | Category: {match.category} | Component: {match.affected_component}\n"
                f"Standards: {', '.join(match.standards) if match.standards else 'General Best Practices'}"
            )
            self.inspector_evidence.setText(str(match.evidence))
            self.inspector_impact.setText(match.impact)
            self.inspector_remediation.setText(match.remediation)
            self.inspector_code.setText(match.code_example or "// No code configuration example provided for this check.")
            self.inspector_verif.setText(f"Verification: {match.verification_step or 'Validate with standard compliance tests.'}")

    def _populate_bugs(self, result: ScanResult):
        bugs = [f for f in result.findings if getattr(f, "is_bug", False)]
        failed_or_warn = [b for b in bugs if b.status in (CheckStatus.FAILED, CheckStatus.WARNING)]

        total_bugs = len(failed_or_warn)
        leaks = sum(1 for b in failed_or_warn if "resource" in b.category.lower() or "leak" in b.title.lower())
        links = sum(1 for b in failed_or_warn if "navigation" in b.category.lower() or "link" in b.title.lower())
        forms = sum(1 for b in failed_or_warn if "form" in b.category.lower())
        crashes = sum(1 for b in failed_or_warn if "exception" in b.category.lower() or "anr" in b.title.lower() or "crash" in b.title.lower())
        banned = sum(1 for b in failed_or_warn if "banned" in b.title.lower() or "safety" in b.category.lower() or "manifest" in b.category.lower())

        self.card_bug_total.val_lbl.setText(str(total_bugs))
        self.card_bug_leaks.val_lbl.setText(str(leaks))
        self.card_bug_links.val_lbl.setText(str(links))
        self.card_bug_forms.val_lbl.setText(str(forms))
        self.card_bug_crashes.val_lbl.setText(str(crashes))
        self.card_bug_banned.val_lbl.setText(str(banned))

        self.bugs_table.setRowCount(0)
        for i, b in enumerate(bugs):
            self.bugs_table.insertRow(i)
            self.bugs_table.setItem(i, 0, QTableWidgetItem(b.check_id))

            sev_item = QTableWidgetItem(b.severity.value.upper())
            sev_item.setForeground(QColor(b.severity.badge_color))
            self.bugs_table.setItem(i, 1, sev_item)

            self.bugs_table.setItem(i, 2, QTableWidgetItem(b.title))
            self.bugs_table.setItem(i, 3, QTableWidgetItem(b.affected_component))

            status_item = QTableWidgetItem(b.status.value.upper())
            if b.status == CheckStatus.PASSED:
                status_item.setForeground(QColor("#00ff9d"))
            else:
                status_item.setForeground(QColor(b.severity.badge_color))
            self.bugs_table.setItem(i, 4, status_item)

        if bugs:
            self.bugs_table.selectRow(0)

    def _filter_bugs(self):
        query = self.bugs_search_edit.text().lower()
        cat_filter = self.bugs_cat_combo.currentText()

        for row in range(self.bugs_table.rowCount()):
            cid = self.bugs_table.item(row, 0).text().lower()
            title = self.bugs_table.item(row, 2).text().lower()
            comp = self.bugs_table.item(row, 3).text().lower()

            matches_query = query in cid or query in title or query in comp
            matches_cat = True
            if cat_filter == "Memory & Handle Leaks":
                matches_cat = "leak" in title or "handle" in title
            elif cat_filter == "Navigation & Broken Links":
                matches_cat = "link" in title or "navigation" in title
            elif cat_filter == "Form & Input Boundaries":
                matches_cat = "form" in title or "input" in title
            elif cat_filter == "Crash & Exception Hazards":
                matches_cat = "exception" in title or "crash" in title or "anr" in title
            elif cat_filter == "Manifest & GUI Defects":
                matches_cat = "manifest" in title or "gui" in title

            self.bugs_table.setRowHidden(row, not (matches_query and matches_cat))

    def _on_bug_selected(self):
        selected_rows = self.bugs_table.selectionModel().selectedRows()
        if not selected_rows or not self.current_result:
            return
        row = selected_rows[0].row()
        cid = self.bugs_table.item(row, 0).text()

        match = next((f for f in self.current_result.findings if f.check_id == cid), None)
        if match:
            self.bug_insp_title.setText(match.title)
            self.bug_insp_component.setText(f"Component: {match.affected_component} | Category: {match.category}")
            self.bug_insp_evidence.setText(str(match.evidence))
            self.bug_insp_patch.setText(match.code_example or match.remediation)

    def _populate_web_history(self, result: ScanResult):
        target = result.target
        if not target or target.target_type != TargetType.WEB:
            self.hist_target_lbl.setText("Applicable to Website targets only.")
            self.card_hist_age.val_lbl.setText("N/A")
            self.card_hist_reg.val_lbl.setText("N/A")
            self.card_hist_exp.val_lbl.setText("N/A")
            self.card_hist_type.val_lbl.setText("N/A (Executable/APK)")
            self.card_hist_size.val_lbl.setText("N/A")
            self.card_hist_admin.val_lbl.setText("N/A")
            return

        hist_data = target.metadata.get("history")
        if not hist_data:
            try:
                hist_data = WebHistoryAnalyzer.analyze(target.target_path, target.metadata).to_dict()
                target.metadata["history"] = hist_data
            except Exception:
                pass

        if not hist_data:
            return

        reg = hist_data.get("registration", {})
        adm = hist_data.get("admin_profile", {})
        timeline = hist_data.get("timeline", [])
        sec = hist_data.get("security_incidents", {})
        foot = hist_data.get("footprint", {})

        self.hist_target_lbl.setText(f"Domain: {hist_data.get('domain', target.target_path)}")
        self.card_hist_age.val_lbl.setText(f"{reg.get('age_years', 0)} Yrs" if reg.get('age_years') else "Active")
        self.card_hist_reg.val_lbl.setText(reg.get("registered_date") or "N/A")
        self.card_hist_exp.val_lbl.setText(reg.get("expiration_date") or "N/A")
        st_text = hist_data.get("site_type", "Web App")
        self.card_hist_type.val_lbl.setText(st_text[:14] + ".." if len(st_text) > 14 else st_text)
        self.card_hist_size.val_lbl.setText(f"~{foot.get('sampled_asset_weight_mb', 1.0)} MB")
        self.card_hist_admin.val_lbl.setText(f"{adm.get('score', 50)}/100")

        self.hist_admin_tier_lbl.setText(f"Tier: {adm.get('tier', 'Intermediate')} (Velocity: {adm.get('maintenance_velocity', 'Moderate')})")
        self.hist_admin_summary_lbl.setText(adm.get("behavior_summary", ""))

        self.hist_admin_strengths_txt.setText("\n".join([f"✔ {s}" for s in adm.get("strengths", [])]) or "Standard baseline.")
        self.hist_admin_blindspots_txt.setText("\n".join([f"⚠ {b}" for b in adm.get("blind_spots", [])]) or "No major blind spots noted.")
        self.hist_sec_risk_lbl.setText(f"Defacement Risk: {sec.get('defacement_risk_level', 'Low')} | Outages: {sec.get('historical_downtime_patterns', 'Stable')}")
        self.hist_sec_notes_txt.setText(sec.get("reputation_notes", "Clean baseline."))

        # Rebuild timeline cards
        while self.hist_timeline_layout.count() > 1:
            item = self.hist_timeline_layout.takeAt(1)
            if item.widget():
                item.widget().deleteLater()

        if timeline:
            for m in timeline:
                card = QFrame()
                card.setStyleSheet("background-color: #12151d; border: 1px solid #1c2230; border-radius: 8px; padding: 10px; margin-bottom: 4px;")
                c_layout = QVBoxLayout(card)

                top = QHBoxLayout()
                yr_lbl = QLabel(f"{m.get('year')} — {m.get('inferred_theme')}")
                yr_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff;")
                snaps = QLabel(f"{m.get('snapshot_count', 0)} Snapshots")
                snaps.setStyleSheet("font-size: 10px; font-weight: 800; color: #00ff9d; background-color: #0b1a16; padding: 2px 6px; border-radius: 4px;")
                top.addWidget(yr_lbl)
                top.addStretch()
                top.addWidget(snaps)
                c_layout.addLayout(top)

                feats = "\n".join([f"• {f}" for f in m.get("major_features_added", [])])
                feat_lbl = QLabel(feats)
                feat_lbl.setStyleSheet("font-size: 11.5px; color: #cbd5e1;")
                c_layout.addWidget(feat_lbl)
                self.hist_timeline_layout.addWidget(card)

        self.hist_timeline_layout.addStretch()

    def _populate_attacks(self, result: ScanResult):
        sim_data = result.target.metadata.get("attack_simulation") if result.target and result.target.metadata else None
        if not sim_data:
            try:
                sim_data = AttackResilienceSimulator.simulate(result).to_dict()
                if result.target:
                    result.target.metadata["attack_simulation"] = sim_data
            except Exception:
                pass

        if not sim_data:
            return

        overall_pct = sim_data.get("overall_survival_chance", 70.0)
        overall_verdict = sim_data.get("overall_verdict", "Moderate Resilience")
        total_atks = sim_data.get("total_attacks_tested", 0)
        hardened = sim_data.get("hardened_count", 0)
        moderate = sim_data.get("moderate_count", 0)
        critical = sim_data.get("critical_exposure_count", 0)
        overall_color = sim_data.get("overall_badge_color", "#ff2a44")

        self.card_atk_survival.val_lbl.setText(f"{overall_pct}%")
        self.card_atk_survival.val_lbl.setStyleSheet(f"font-size: 18px; font-weight: 800; color: {overall_color};")
        self.card_atk_verdict.val_lbl.setText(overall_verdict[:14] + ".." if len(overall_verdict) > 14 else overall_verdict)
        self.card_atk_total.val_lbl.setText(str(total_atks))
        self.card_atk_hardened.val_lbl.setText(str(hardened))
        self.card_atk_moderate.val_lbl.setText(str(moderate))
        self.card_atk_critical.val_lbl.setText(str(critical))

        self.atk_table.setRowCount(0)
        attacks = sim_data.get("attacks", [])
        for i, atk in enumerate(attacks):
            self.atk_table.insertRow(i)
            self.atk_table.setItem(i, 0, QTableWidgetItem(atk.get("attack_id", "")))
            self.atk_table.setItem(i, 1, QTableWidgetItem(atk.get("name", "")))
            self.atk_table.setItem(i, 2, QTableWidgetItem(atk.get("category", "")))

            pct_val = atk.get("survival_chance", 50.0)
            pct_item = QTableWidgetItem(f"{pct_val}%")
            pct_item.setForeground(QColor(atk.get("verdict_badge_color", "#ff2a44")))
            self.atk_table.setItem(i, 3, pct_item)

            v_item = QTableWidgetItem(atk.get("verdict", ""))
            v_item.setForeground(QColor(atk.get("verdict_badge_color", "#ff2a44")))
            self.atk_table.setItem(i, 4, v_item)

        if attacks:
            self.atk_table.selectRow(0)

    def _on_attack_selected(self):
        if not self.current_result:
            return
        selected = self.atk_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        atk_id = self.atk_table.item(row, 0).text()

        sim_data = self.current_result.target.metadata.get("attack_simulation") if self.current_result.target else None
        if not sim_data:
            return

        match = next((a for a in sim_data.get("attacks", []) if a.get("attack_id") == atk_id), None)
        if match:
            pct = match.get("survival_chance", 50.0)
            color = match.get("verdict_badge_color", "#ff2a44")
            self.atk_insp_title.setText(f"{match.get('name')} ({match.get('attack_id')})")
            self.atk_insp_survival_bar.setText(f"Survival Probability: {pct}% — {match.get('verdict')}")
            self.atk_insp_survival_bar.setStyleSheet(f"font-size: 13px; font-weight: 800; color: {color}; background: #0c1322; padding: 7px 12px; border-radius: 6px; border-left: 4px solid {color};")
            self.atk_insp_objective.setText(match.get("threat_objective", ""))
            self.atk_insp_mechanics.setText(match.get("vector_description", ""))

            defs = "\n".join([f"✔ {d}" for d in match.get("mitigating_controls_active", [])]) or "Standard platform baseline."
            self.atk_insp_defenses.setText(defs)

            pens = []
            for v in match.get("contributing_vulnerabilities", []):
                pens.append(f"✘ [{v.get('impact_penalty', 0):+.0f}%] {v.get('title')}: {v.get('description')}")
            self.atk_insp_penalties.setText("\n".join(pens) if pens else "✔ Zero vulnerability penalties flagged.")

            steps = []
            for idx, h in enumerate(match.get("hardening_steps", []), 1):
                steps.append(f"{idx}. {h}")
            self.atk_insp_hardening.setText("\n".join(steps))

    def _filter_attacks(self, mode: str):
        for row in range(self.atk_table.rowCount()):
            cat = self.atk_table.item(row, 2).text().lower()
            pct_str = self.atk_table.item(row, 3).text().replace("%", "").strip()
            try:
                pct = float(pct_str)
            except ValueError:
                pct = 50.0

            if mode == "all":
                show = True
            elif mode == "web":
                show = "web" in cat
            elif mode == "win":
                show = "windows" in cat or "os" in cat
            elif mode == "infra":
                show = "infra" in cat or "identity" in cat or "cross" in cat
            elif mode == "crit":
                show = pct < 50.0
            else:
                show = True
            self.atk_table.setRowHidden(row, not show)

    # =========================================================================
    # QA AUTOMATION CONTROLLER METHODS
    # =========================================================================
    def _populate_automation(self, result: ScanResult):
        target = result.target
        if not target:
            return

        auto_data = target.metadata.get("automation_report") if target.metadata else None
        if not auto_data:
            try:
                auto_data = PopularToolsAutomationTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["automation_report"] = auto_data
            except Exception:
                auto_data = None

        if not auto_data:
            return

        self._current_qa_report = auto_data

        p_tool = auto_data.get("primary_tool", "Primary Tool")
        s_tool = auto_data.get("secondary_tool", "Secondary Tool")
        plat = auto_data.get("platform", "Platform")
        score = auto_data.get("quality_score", 100.0)
        status = auto_data.get("overall_status", "PRODUCTION READY")

        status_color = "#00ff9d" if "PROD" in status else "#ffb800" if "ATTENTION" in status else "#ff2a44"

        self.qa_target_lbl.setText(
            f"Target: {auto_data.get('target_name', '')}  |  Platform: {plat}  |  Primary: {p_tool}  |  Secondary: {s_tool}"
        )

        self.card_qa_score.val_lbl.setText(f"{score:.1f}%")
        self.card_qa_score.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {status_color};")
        self.card_qa_tests.val_lbl.setText(str(auto_data.get("total_tests", 0)))
        self.card_qa_passed.val_lbl.setText(str(auto_data.get("passed_tests", 0)))
        self.card_qa_defects.val_lbl.setText(str(auto_data.get("failed_tests", 0)))
        self.card_qa_flaky.val_lbl.setText(f"{auto_data.get('flaky_count', 0)} Flaky" if auto_data.get('flaky_count', 0) > 0 else "0 Risk")
        self.card_qa_time.val_lbl.setText(f"{auto_data.get('duration_seconds', 0.0)}s")

        self.btn_fltr_qa_primary.setText(f"{p_tool} Only")
        self.btn_fltr_qa_secondary.setText(f"{s_tool} Only")

        self.qa_script_selector.blockSignals(True)
        self.qa_script_selector.clear()
        self.qa_script_selector.addItem(f"Primary Automation Script ({p_tool})")
        self.qa_script_selector.addItem(f"Secondary Automation Script ({s_tool})")
        self.qa_script_selector.blockSignals(False)

        self._on_qa_script_tool_changed(0)
        self.qa_cicd_txt.setText(auto_data.get("ci_cd_pipeline_yaml", ""))
        self.qa_deliverable_txt.setText(auto_data.get("copiable_client_markdown", ""))

        # Populate table
        self.qa_table.setRowCount(0)
        all_cases = []
        for suite in auto_data.get("suites", []):
            for tc in suite.get("test_cases", []):
                all_cases.append(tc)

        for i, tc in enumerate(all_cases):
            self.qa_table.insertRow(i)
            item_id = QTableWidgetItem(tc.get("test_id", ""))
            item_tool = QTableWidgetItem(tc.get("tool", ""))
            item_name = QTableWidgetItem(tc.get("name", ""))
            st = tc.get("status", "PASSED")
            item_st = QTableWidgetItem(st)
            col = "#00ff9d" if st == "PASSED" else "#ff2a44" if st == "FAILED" else "#ffb800"
            item_st.setForeground(QColor(col))
            item_dur = QTableWidgetItem(f"{tc.get('duration_ms', 0)}ms")

            item_id.setData(Qt.UserRole, tc)
            self.qa_table.setItem(i, 0, item_id)
            self.qa_table.setItem(i, 1, item_tool)
            self.qa_table.setItem(i, 2, item_name)
            self.qa_table.setItem(i, 3, item_st)
            self.qa_table.setItem(i, 4, item_dur)

        if all_cases:
            self.qa_table.selectRow(0)

    def _on_qa_case_selected(self):
        selected = self.qa_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        item = self.qa_table.item(row, 0)
        if not item:
            return
        tc = item.data(Qt.UserRole)
        if not tc:
            return

        st = tc.get("status", "PASSED")
        col = "#00ff9d" if st == "PASSED" else "#ff2a44" if st == "FAILED" else "#ffb800"
        self.qa_insp_title.setText(f"{tc.get('name', '')} ({tc.get('test_id', '')})")
        self.qa_insp_title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {col};")

        self.qa_insp_meta.setText(
            f"Tool: {tc.get('tool', '')}  |  Suite: {tc.get('suite', '')}  |  Status: {st}  |  Duration: {tc.get('duration_ms', 0)}ms  |  Flaky Risk: {tc.get('flaky_risk', 'Low')}"
        )
        self.qa_insp_meta.setStyleSheet(
            f"font-size: 12px; font-weight: 700; color: {col}; background: #0c1322; padding: 7px 12px; border-radius: 6px; border-left: 4px solid {col};"
        )
        self.qa_insp_assertion.setText(tc.get("assertion", ""))
        self.qa_insp_expected.setText(tc.get("expected", ""))
        self.qa_insp_actual.setText(tc.get("actual", ""))
        self.qa_insp_repro.setText("\n".join(tc.get("reproduction_steps", [])) or "Single automated assertion execution.")
        self.qa_insp_patch.setText(tc.get("developer_patch", "") or "No remediation required. Assertion passed baseline verification.")

    def _on_qa_script_tool_changed(self, idx: int):
        report = getattr(self, "_current_qa_report", None)
        if not report:
            return
        if idx == 0:
            self.qa_script_txt.setText(report.get("ready_to_run_script_primary", ""))
        else:
            self.qa_script_txt.setText(report.get("ready_to_run_script_secondary", ""))

    def _filter_qa_cases(self, mode: str):
        report = getattr(self, "_current_qa_report", {})
        p_tool = report.get("primary_tool", "").lower()
        s_tool = report.get("secondary_tool", "").lower()

        for row in range(self.qa_table.rowCount()):
            tool = self.qa_table.item(row, 1).text().lower()
            st = self.qa_table.item(row, 3).text().upper()

            if mode == "all":
                show = True
            elif mode == "passed":
                show = (st == "PASSED")
            elif mode == "defects":
                show = (st != "PASSED")
            elif mode == "primary":
                show = (p_tool in tool or tool in p_tool)
            elif mode == "secondary":
                show = (s_tool in tool or tool in s_tool)
            else:
                show = True
            self.qa_table.setRowHidden(row, not show)

    def _copy_qa_report_to_clipboard(self):
        text = self.qa_deliverable_txt.toPlainText().strip()
        if not text:
            rep = getattr(self, "_current_qa_report", {})
            text = rep.get("copiable_client_markdown", "")
        if not text:
            QMessageBox.warning(self, "No Report Available", "Please execute or load a scan to generate the QA automation report.")
            return

        QApplication.clipboard().setText(text)
        QMessageBox.information(
            self,
            "Deliverable Copied",
            "Professional QA Automation Client Deliverable copied to clipboard!\n\n"
            "Ready to paste directly into Slack, Teams, Email, Jira, or Google Docs."
        )

    def _copy_qa_script_to_clipboard(self):
        code = self.qa_script_txt.toPlainText().strip()
        if not code:
            QMessageBox.warning(self, "No Script", "No automation script available to copy.")
            return
        QApplication.clipboard().setText(code)
        QMessageBox.information(self, "Script Copied", "Ready-to-run automation test script copied to clipboard!")

    def _copy_qa_cicd_to_clipboard(self):
        yaml_text = self.qa_cicd_txt.toPlainText().strip()
        if not yaml_text:
            QMessageBox.warning(self, "No CI/CD Config", "No CI/CD pipeline YAML available to copy.")
            return
        QApplication.clipboard().setText(yaml_text)
        QMessageBox.information(self, "Pipeline Copied", "CI/CD YAML pipeline specification copied to clipboard!")

    def _export_qa_html(self):
        report = getattr(self, "_current_qa_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("automation_report")
        if not report:
            QMessageBox.warning(self, "No QA Report", "Please execute or load a scan first to generate QA automation data.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save QA Deliverable HTML Report", "QA_Automation_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_qa_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional QA Deliverable HTML saved to:\n{file_path}")

    def _rerun_qa_tests(self):
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            target_str = self.target_path_edit.text().strip() or "https://pmec.ac.in"
            target_type = self._selected_target_type
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = PopularToolsAutomationTester.run_tests(target, target.metadata, findings)
            target.metadata["automation_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_automation(self.current_result)
            QMessageBox.information(self, "Suite Executed", f"Successfully executed automation suite for {target.display_name}!")
        except Exception as e:
            QMessageBox.critical(self, "Execution Error", f"Failed to run automation suite:\n{str(e)}")

    # =========================================================================
    # REST & BACKEND API CONTROLLER METHODS
    # =========================================================================
    def _populate_api(self, result: ScanResult):
        target = result.target
        if not target:
            return

        api_data = target.metadata.get("api_report") if target.metadata else None
        if not api_data:
            try:
                api_data = ApiTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["api_report"] = api_data
            except Exception:
                api_data = None

        if not api_data:
            return

        self._current_api_report = api_data

        base = api_data.get("base_url", "")
        spec = api_data.get("specification_format", "REST Service")
        score = api_data.get("quality_score", 100.0)
        status = api_data.get("overall_status", "PRODUCTION READY")
        total_ep = api_data.get("total_endpoints", 0)
        total_t = api_data.get("total_tests", 0)
        passed_t = api_data.get("passed_tests", 0)
        failed_t = api_data.get("failed_tests", 0)
        rl_active = api_data.get("rate_limiting_active", False)

        status_color = "#00ff9d" if "PROD" in status else "#ffb800" if "ATTENTION" in status else "#ff3366"

        self.api_target_lbl.setText(
            f"Base Endpoint: {base}  |  Spec: {spec}  |  Endpoints: {total_ep}  |  Status: {status}"
        )

        self.card_api_score.val_lbl.setText(f"{score:.1f}%")
        self.card_api_score.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {status_color};")
        self.card_api_endpoints.val_lbl.setText(str(total_ep))
        self.card_api_tests.val_lbl.setText(str(total_t))
        self.card_api_defects.val_lbl.setText(str(failed_t))
        self.card_api_rate_limit.val_lbl.setText("ACTIVE" if rl_active else "UNTHROTTLED")
        self.card_api_rate_limit.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {'#00ff9d' if rl_active else '#ffb800'};")

        cases = api_data.get("test_cases", [])
        avg_lat = round(sum(tc.get("latency_ms", 0) for tc in cases) / max(1, len(cases))) if cases else 45
        self.card_api_latency.val_lbl.setText(f"{avg_lat}ms")

        self.api_python_txt.setText(api_data.get("ready_to_run_python_script", ""))
        self.api_postman_txt.setText(api_data.get("postman_collection_json", ""))
        self.api_deliverable_txt.setText(api_data.get("copiable_client_markdown", ""))

        # Populate table
        self.api_table.setRowCount(0)
        for i, tc in enumerate(cases):
            self.api_table.insertRow(i)
            item_id = QTableWidgetItem(tc.get("test_id", ""))
            m_str = tc.get("method", "GET")
            item_m = QTableWidgetItem(m_str)
            m_col = "#00d4ff" if m_str == "GET" else "#00ff9d" if m_str == "POST" else "#ffb800" if m_str == "PUT" else "#ff3366"
            item_m.setForeground(QColor(m_col))

            item_ep = QTableWidgetItem(tc.get("endpoint", ""))
            item_cat = QTableWidgetItem(tc.get("category", ""))
            st = tc.get("status", "PASSED")
            item_st = QTableWidgetItem(st)
            st_col = "#00ff9d" if st == "PASSED" else "#ff2a44" if st == "FAILED" else "#ffb800"
            item_st.setForeground(QColor(st_col))
            item_lat = QTableWidgetItem(f"{tc.get('latency_ms', 0)}ms")

            item_id.setData(Qt.UserRole, tc)
            self.api_table.setItem(i, 0, item_id)
            self.api_table.setItem(i, 1, item_m)
            self.api_table.setItem(i, 2, item_ep)
            self.api_table.setItem(i, 3, item_cat)
            self.api_table.setItem(i, 4, item_st)
            self.api_table.setItem(i, 5, item_lat)

        if cases:
            self.api_table.selectRow(0)

    def _on_api_test_selected(self):
        selected = self.api_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        item = self.api_table.item(row, 0)
        if not item:
            return
        tc = item.data(Qt.UserRole)
        if not tc:
            return

        st = tc.get("status", "PASSED")
        col = "#00ff9d" if st == "PASSED" else "#ff2a44" if st == "FAILED" else "#ffb800"

        self.api_insp_title.setText(f"{tc.get('test_name', '')} ({tc.get('test_id', '')})")
        self.api_insp_title.setStyleSheet(f"font-size: 15px; font-weight: 800; color: {col};")

        self.api_insp_meta.setText(
            f"Method: {tc.get('method', '')}  |  Endpoint: {tc.get('endpoint', '')}  |  Category: {tc.get('category', '')}  |  Status: {st}  |  Latency: {tc.get('latency_ms', 0)}ms"
        )
        self.api_insp_meta.setStyleSheet(
            f"font-size: 12px; font-weight: 700; color: {col}; background: #0c1322; padding: 7px 12px; border-radius: 6px; border-left: 4px solid {col};"
        )

        self.api_insp_expected.setText(tc.get("expected_status", ""))
        self.api_insp_actual.setText(f"{tc.get('actual_status', '')}\n{tc.get('details', '')}")
        self.api_insp_curl.setText(tc.get("reproduction_curl", "") or f"curl -s '{tc.get('endpoint', '')}'")
        self.api_insp_patch.setText(tc.get("developer_patch", "") or "No remediation required. Endpoint satisfied contract verification.")

    def _filter_api_cases(self, mode: str):
        for row in range(self.api_table.rowCount()):
            cat = self.api_table.item(row, 3).text().lower()
            st = self.api_table.item(row, 4).text().upper()

            if mode == "all":
                show = True
            elif mode == "schema":
                show = "contract" in cat or "schema" in cat
            elif mode == "fuzz":
                show = "boundary" in cat or "fuzz" in cat
            elif mode == "auth":
                show = "auth" in cat or "access" in cat
            elif mode == "defects":
                show = (st != "PASSED")
            else:
                show = True
            self.api_table.setRowHidden(row, not show)

    def _copy_api_report_to_clipboard(self):
        text = self.api_deliverable_txt.toPlainText().strip()
        if not text:
            rep = getattr(self, "_current_api_report", {})
            text = rep.get("copiable_client_markdown", "")
        if not text:
            QMessageBox.warning(self, "No Report Available", "Please execute or load a scan to generate the API testing report.")
            return

        QApplication.clipboard().setText(text)
        QMessageBox.information(
            self,
            "Deliverable Copied",
            "Professional REST & Backend API Audit Report copied to clipboard!\n\n"
            "Ready to paste directly into Slack, Teams, Email, Jira, or Google Docs."
        )

    def _copy_api_python_to_clipboard(self):
        code = self.api_python_txt.toPlainText().strip()
        if not code:
            QMessageBox.warning(self, "No Code", "No Python test suite available to copy.")
            return
        QApplication.clipboard().setText(code)
        QMessageBox.information(self, "Script Copied", "Ready-to-run Python API test suite copied to clipboard!")

    def _copy_postman_to_clipboard(self):
        json_txt = self.api_postman_txt.toPlainText().strip()
        if not json_txt:
            QMessageBox.warning(self, "No Postman Collection", "No Postman collection available to copy.")
            return
        QApplication.clipboard().setText(json_txt)
        QMessageBox.information(self, "Collection Copied", "Postman Collection v2.1.0 JSON copied to clipboard!")

    def _export_postman_collection(self):
        report = getattr(self, "_current_api_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("api_report")
        if not report:
            QMessageBox.warning(self, "No API Report", "Please execute or load a scan first to generate Postman collection.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Postman Collection", "CHARLO_API_Collection.postman_collection.json", "JSON Files (*.json)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("postman_collection_json", "{}"))
            QMessageBox.information(self, "Collection Exported", f"Postman Collection v2.1.0 successfully saved to:\n{file_path}\n\nReady to import into Postman or run with Newman CLI.")

    def _export_api_html(self):
        report = getattr(self, "_current_api_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("api_report")
        if not report:
            QMessageBox.warning(self, "No API Report", "Please execute or load a scan first to generate API test data.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save API Quality Deliverable HTML Report", "API_Quality_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_api_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional API Deliverable HTML saved to:\n{file_path}")

    def _rerun_api_tests(self):
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            target_str = self.target_path_edit.text().strip() or "https://pmec.ac.in"
            target_type = self._selected_target_type
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = ApiTester.run_tests(target, target.metadata, findings)
            target.metadata["api_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_api(self.current_result)
            QMessageBox.information(self, "API Suite Executed", f"Successfully executed REST & API test suite for {target.display_name}!")
        except Exception as e:
            QMessageBox.critical(self, "Execution Error", f"Failed to run API suite:\n{str(e)}")

    # =========================================================================
    # PERFORMANCE & CONCURRENCY CONTROLLER METHODS
    # =========================================================================
    def _populate_perf(self, result: ScanResult):
        target = result.target
        if not target:
            return

        perf_data = target.metadata.get("performance_report") if target.metadata else None
        if not perf_data:
            try:
                perf_data = PerformanceTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["performance_report"] = perf_data
            except Exception:
                perf_data = None

        if not perf_data:
            return

        self._current_perf_report = perf_data

        name = perf_data.get("target_name", target.display_name)
        url = perf_data.get("target_url", target.target_path)
        profile = perf_data.get("load_profile", "Standard Load")
        vus = perf_data.get("virtual_users", 50)
        rps = perf_data.get("throughput_rps", 0.0)
        sla_st = perf_data.get("sla_status", "COMPLIANT")
        grade = perf_data.get("performance_grade", "A")
        total_reqs = perf_data.get("total_requests", 0)
        err_rate = perf_data.get("error_rate_pct", 0.0)
        pct = perf_data.get("percentiles", {})

        sla_col = "#00ff9d" if "COMPLIANT" in sla_st else "#ffb800" if "DEGRADED" in sla_st else "#ff3366"
        grade_col = "#00ff9d" if grade in ("A", "B") else "#ffb800" if grade == "C" else "#ff3366"

        self.perf_target_lbl.setText(
            f"Target: {name} ({url})  |  Profile: {profile}  |  Concurrency: {vus} VUs  |  SLA: {sla_st} (Grade {grade})"
        )

        self.card_perf_rps.val_lbl.setText(f"{rps:.1f} RPS")
        self.card_perf_p95.val_lbl.setText(f"{pct.get('p95_ms', 0):.1f}ms")
        self.card_perf_p95.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {'#00ff9d' if pct.get('p95_ms', 0) <= 500 else '#ff3366'};")
        self.card_perf_avg.val_lbl.setText(f"{pct.get('avg_ms', 0):.1f}ms")
        self.card_perf_error.val_lbl.setText(f"{err_rate:.2f}%")
        self.card_perf_error.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {'#00ff9d' if err_rate <= 1.0 else '#ff3366'};")
        self.card_perf_sla.val_lbl.setText(f"Grade {grade}")
        self.card_perf_sla.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {grade_col};")
        self.card_perf_total.val_lbl.setText(f"{total_reqs:,}")

        # Populate Percentiles Table
        self.perf_percentiles_table.setRowCount(0)
        percentile_rows = [
            ("Minimum (Fastest)", f"{pct.get('min_ms', 0):.1f} ms", "Baseline connect time", "Optimal", "#00ff9d"),
            ("Average (Mean)", f"{pct.get('avg_ms', 0):.1f} ms", "Normal working average", "Conformant", "#38bdf8"),
            ("50th Percentile (p50)", f"{pct.get('median_p50_ms', 0):.1f} ms", "Median transaction speed", "Conformant", "#38bdf8"),
            ("90th Percentile (p90)", f"{pct.get('p90_ms', 0):.1f} ms", "Upper load boundary", "Stable", "#facc15"),
            ("95th Percentile (p95)", f"{pct.get('p95_ms', 0):.1f} ms", "Critical SLA Threshold (< 500ms)", "PASS" if pct.get('p95_ms', 0) <= 500 else "BREACH", "#00ff9d" if pct.get('p95_ms', 0) <= 500 else "#ff3366"),
            ("99th Percentile (p99)", f"{pct.get('p99_ms', 0):.1f} ms", "Worst 1% Tail Latency (< 1200ms)", "PASS" if pct.get('p99_ms', 0) <= 1200 else "TAIL DELAY", "#00ff9d" if pct.get('p99_ms', 0) <= 1200 else "#ff3366"),
            ("Maximum Peak Spike", f"{pct.get('max_ms', 0):.1f} ms", "Worst single transaction recorded", "Outlier", "#d946ef"),
        ]
        for idx, (level_s, val_s, sla_s, gate_s, col_s) in enumerate(percentile_rows):
            self.perf_percentiles_table.insertRow(idx)
            item_lvl = QTableWidgetItem(level_s)
            item_val = QTableWidgetItem(val_s)
            item_val.setForeground(QColor(col_s))
            item_sla = QTableWidgetItem(sla_s)
            item_gate = QTableWidgetItem(gate_s)
            item_gate.setForeground(QColor(col_s))
            self.perf_percentiles_table.setItem(idx, 0, item_lvl)
            self.perf_percentiles_table.setItem(idx, 1, item_val)
            self.perf_percentiles_table.setItem(idx, 2, item_sla)
            self.perf_percentiles_table.setItem(idx, 3, item_gate)

        # Populate Status Codes Table
        self.perf_codes_table.setRowCount(0)
        for idx, (code_s, cnt_i) in enumerate(perf_data.get("status_codes_distribution", {}).items()):
            self.perf_codes_table.insertRow(idx)
            item_code = QTableWidgetItem(code_s)
            c_col = "#00ff9d" if "200" in code_s else "#ffb800" if "429" in code_s else "#ff3366"
            item_code.setForeground(QColor(c_col))
            item_cnt = QTableWidgetItem(str(cnt_i))
            pct_val = (cnt_i / max(1, total_reqs)) * 100.0
            item_pct = QTableWidgetItem(f"{pct_val:.1f}%")
            self.perf_codes_table.setItem(idx, 0, item_code)
            self.perf_codes_table.setItem(idx, 1, item_cnt)
            self.perf_codes_table.setItem(idx, 2, item_pct)

        # Bottleneck Text
        self.perf_bottleneck_txt.setText(perf_data.get("bottleneck_diagnosis", "No critical bottleneck observed."))

        # SLA Details Tab
        sla_report_text = f"""ENTERPRISE SLA VERIFICATION BREAKDOWN
================================================================================
Target URL:           {url}
Throughput Benchmark: {rps:.1f} Requests Per Second (RPS)
Concurrency Load:     {vus} Virtual Users
Capacity Compliance:  {sla_st} (Grade {grade})

1. SLA GATE VERIFICATION:
  • p95 Latency SLA (< 500ms):    {pct.get('p95_ms', 0):.1f}ms -> {'[COMPLIANT - PASS]' if pct.get('p95_ms', 0) <= 500 else '[BREACH - ACTION REQUIRED]'}
  • p99 Latency SLA (< 1200ms):   {pct.get('p99_ms', 0):.1f}ms -> {'[COMPLIANT - PASS]' if pct.get('p99_ms', 0) <= 1200 else '[BREACH - ACTION REQUIRED]'}
  • Error Rate SLA (< 1.0%):      {err_rate:.2f}% -> {'[COMPLIANT - PASS]' if err_rate <= 1.0 else '[BREACH - EXCESSIVE ERRORS]'}
  • HTTP 504 Gateway Timeouts:    {perf_data.get('status_codes_distribution', {}).get('504 Gateway Timeout', 0)} occurrences

2. ARCHITECTURAL CAPACITY RECOMMENDATIONS:
  • Connection Pooling: Keep-alive reuse eliminates per-request TLS negotiation overhead (~80ms).
  • Response Compression: Ensure Brotli/Gzip compression enabled on API endpoints returning >1KB.
  • Edge Caching: Set explicit HTTP Cache-Control: max-age headers for cacheable public resources.
  • Concurrency Ceiling: System handles {vus} VUs with {rps:.1f} RPS sustained throughput.
================================================================================
"""
        self.perf_sla_details_txt.setText(sla_report_text)

        # Tab contents
        self.perf_k6_txt.setText(perf_data.get("k6_script_content", ""))
        self.perf_jmeter_txt.setText(perf_data.get("jmeter_jmx_content", ""))
        self.perf_deliverable_txt.setText(perf_data.get("copiable_client_markdown", ""))

    def _on_perf_profile_changed(self):
        txt = self.perf_profile_combo.currentText()
        if "50 VUs" in txt:
            self.perf_vus_spin.setValue(50)
            self.perf_duration_spin.setValue(30)
        elif "5 VUs" in txt:
            self.perf_vus_spin.setValue(5)
            self.perf_duration_spin.setValue(10)
        elif "200 VUs" in txt:
            self.perf_vus_spin.setValue(200)
            self.perf_duration_spin.setValue(20)
        elif "25 VUs" in txt:
            self.perf_vus_spin.setValue(25)
            self.perf_duration_spin.setValue(60)

    def _run_perf_simulation(self):
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            target_str = self.target_path_edit.text().strip() or "https://pmec.ac.in"
            target_type = self._selected_target_type
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        vus = self.perf_vus_spin.value()
        duration = self.perf_duration_spin.value()
        prof_txt = self.perf_profile_combo.currentText()
        prof_key = "smoke" if "5 VUs" in prof_txt else "stress" if "200 VUs" in prof_txt else "soak" if "25 VUs" in prof_txt else "load"

        try:
            report = PerformanceTester.run_tests(
                target=target,
                context=target.metadata,
                findings=findings,
                profile_key=prof_key,
                custom_vus=vus,
                custom_duration=duration,
            )
            target.metadata["performance_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_perf(self.current_result)
            QMessageBox.information(
                self, "Load Simulation Complete",
                f"Concurrency load simulation completed for {target.display_name}!\n\n"
                f"Virtual Users: {report.virtual_users} VUs\n"
                f"Throughput: {report.throughput_rps} RPS\n"
                f"p95 Latency: {report.percentiles.p95_ms}ms\n"
                f"SLA Compliance: {report.sla_status} (Grade {report.performance_grade})"
            )
        except Exception as e:
            QMessageBox.critical(self, "Simulation Error", f"Failed to execute load simulation:\n{str(e)}")

    def _copy_perf_markdown(self):
        md = self.perf_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No performance benchmark deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Corporate performance audit deliverable copied to clipboard!")

    def _copy_k6_script(self):
        code = self.perf_k6_txt.toPlainText().strip()
        if not code:
            QMessageBox.warning(self, "No k6 Script", "No k6 load test script available to copy.")
            return
        QApplication.clipboard().setText(code)
        QMessageBox.information(self, "Script Copied", "Grafana k6 load test script copied to clipboard!")

    def _copy_jmeter_jmx(self):
        xml_txt = self.perf_jmeter_txt.toPlainText().strip()
        if not xml_txt:
            QMessageBox.warning(self, "No JMeter Plan", "No JMeter XML test plan available to copy.")
            return
        QApplication.clipboard().setText(xml_txt)
        QMessageBox.information(self, "JMeter Plan Copied", "Apache JMeter 5.x test plan XML copied to clipboard!")

    def _export_k6_script(self):
        report = getattr(self, "_current_perf_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("performance_report")
        if not report:
            QMessageBox.warning(self, "No Performance Report", "Please execute a scan or simulation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Grafana k6 Load Test Script", "k6_load_test.js", "JavaScript Files (*.js)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("k6_script_content", ""))
            QMessageBox.information(self, "k6 Script Exported", f"Grafana k6 test script saved to:\n{file_path}\n\nRun with: k6 run {os.path.basename(file_path)}")

    def _export_jmeter_jmx(self):
        report = getattr(self, "_current_perf_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("performance_report")
        if not report:
            QMessageBox.warning(self, "No Performance Report", "Please execute a scan or simulation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Apache JMeter Test Plan", "jmeter_test_plan.jmx", "JMeter JMX Files (*.jmx)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("jmeter_jmx_content", ""))
            QMessageBox.information(self, "JMeter Plan Exported", f"Apache JMeter XML Plan saved to:\n{file_path}\n\nRun with: jmeter -n -t {os.path.basename(file_path)} -l results.jtl")

    def _export_perf_html(self):
        report = getattr(self, "_current_perf_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("performance_report")
        if not report:
            QMessageBox.warning(self, "No Performance Report", "Please execute a scan or simulation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Performance Deliverable HTML Report", "Performance_Load_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_performance_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional Performance Deliverable HTML saved to:\n{file_path}")

    # =========================================================================
    # CI/CD QUALITY GATES & PIPELINE CONTROLLER METHODS
    # =========================================================================
    def _populate_cicd(self, result: ScanResult):
        target = result.target
        if not target:
            return

        cicd_data = target.metadata.get("cicd_report") if target.metadata else None
        if not cicd_data:
            try:
                crit_limit = self.cicd_crit_spin.value()
                high_limit = self.cicd_high_spin.value()
                score_limit = float(self.cicd_score_spin.value())
                rule = QualityGateRule(
                    max_critical_findings=crit_limit,
                    max_high_findings=high_limit,
                    min_overall_score=score_limit,
                )
                cicd_data = CiCdGenerator.run_pipeline_generation(target, result, rule).to_dict()
                target.metadata["cicd_report"] = cicd_data
            except Exception:
                cicd_data = None

        if not cicd_data:
            return

        self._current_cicd_report = cicd_data

        name = cicd_data.get("target_name", target.display_name)
        path = cicd_data.get("target_path", target.target_path)
        gate = cicd_data.get("gate_result", {})
        rule = cicd_data.get("gate_rule", {})
        passed = gate.get("passed", True)
        status = gate.get("status", "GATE PASSED")
        score = gate.get("overall_score", 100.0)
        viols_cnt = gate.get("total_violations", 0)

        status_col = "#00ff9d" if passed else "#ff3366"

        self.cicd_target_lbl.setText(
            f"Target: {name} ({path})  |  Verdict: {status}  |  Health Score: {score:.1f}%  |  Violations: {viols_cnt}"
        )

        self.card_cicd_status.val_lbl.setText(status)
        self.card_cicd_status.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {status_col};")
        self.card_cicd_score.val_lbl.setText(f"{score:.1f}%")
        self.card_cicd_viols.val_lbl.setText(f"{viols_cnt} Issues")
        self.card_cicd_viols.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {'#00ff9d' if viols_cnt == 0 else '#ff2a44'};")
        self.card_cicd_crit.val_lbl.setText(f"<= {rule.get('max_critical_findings', 0)}")
        self.card_cicd_high.val_lbl.setText(f"<= {rule.get('max_high_findings', 0)}")
        self.card_cicd_sla.val_lbl.setText(f"<= {rule.get('max_p95_latency_ms', 600)}ms")

        # Violations checklist text
        viols_lines = []
        for v in gate.get("violation_details", []):
            icon = "✔" if passed else "✖"
            viols_lines.append(f" {icon} {v}")
        self.cicd_violations_txt.setText("\n".join(viols_lines))

        # Remediation advice text
        advice_lines = []
        for r in gate.get("remediation_advice", []):
            advice_lines.append(f" • ACTION: {r}")
        self.cicd_advice_txt.setText("\n".join(advice_lines) if advice_lines else "✔ No remediation required. All quality gate criteria cleared for production deployment.")

        # Tabs content
        self.cicd_github_txt.setText(cicd_data.get("github_actions_yaml", ""))
        self.cicd_gitlab_txt.setText(cicd_data.get("gitlab_ci_yaml", ""))
        self.cicd_jenkins_txt.setText(cicd_data.get("jenkinsfile_content", ""))
        self.cicd_junit_txt.setText(cicd_data.get("junit_xml_content", ""))
        self.cicd_deliverable_txt.setText(cicd_data.get("copiable_client_markdown", ""))

    def _evaluate_custom_gate(self):
        if not self.current_result or not self.current_result.target:
            target_str = self.target_path_edit.text().strip() or "https://pmec.ac.in"
            target_type = self._selected_target_type
            from ..core.models import ScanTarget, ScanResult, ScanMetrics
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            self.current_result = ScanResult(
                target=target,
                level=ScanLevel.BASIC,
                findings=[],
                metrics=ScanMetrics(total_checks=0, passed=0),
            )

        target = self.current_result.target
        crit_limit = self.cicd_crit_spin.value()
        high_limit = self.cicd_high_spin.value()
        score_limit = float(self.cicd_score_spin.value())

        rule = QualityGateRule(
            max_critical_findings=crit_limit,
            max_high_findings=high_limit,
            min_overall_score=score_limit,
        )

        try:
            report = CiCdGenerator.run_pipeline_generation(target, self.current_result, rule)
            target.metadata["cicd_report"] = report.to_dict()
            self._populate_cicd(self.current_result)
            gate = report.gate_result
            msg_type = QMessageBox.information if gate.passed else QMessageBox.warning
            msg_type(
                self, "Quality Gate Evaluated",
                f"Evaluation Completed for {target.display_name}!\n\n"
                f"Verdict: {gate.status}\n"
                f"Health Score: {gate.overall_score:.1f}%\n"
                f"Policy Violations: {gate.total_violations}\n\n"
                f"Policy: Max Criticals<={rule.max_critical_findings}, Max Highs<={rule.max_high_findings}, Min Score>={rule.min_overall_score}%"
            )
        except Exception as e:
            QMessageBox.critical(self, "Gate Evaluation Error", f"Failed to evaluate gate policy:\n{str(e)}")

    def _copy_cicd_markdown(self):
        md = self.cicd_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No CI/CD deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Corporate CI/CD Quality Gate deliverable copied to clipboard!")

    def _copy_github_actions(self):
        txt = self.cicd_github_txt.toPlainText().strip()
        if not txt:
            QMessageBox.warning(self, "No Workflow", "No GitHub Actions workflow available to copy.")
            return
        QApplication.clipboard().setText(txt)
        QMessageBox.information(self, "Workflow Copied", "GitHub Actions workflow YAML copied to clipboard!")

    def _copy_gitlab_ci(self):
        txt = self.cicd_gitlab_txt.toPlainText().strip()
        if not txt:
            QMessageBox.warning(self, "No Pipeline", "No GitLab CI configuration available to copy.")
            return
        QApplication.clipboard().setText(txt)
        QMessageBox.information(self, "Pipeline Copied", "GitLab CI pipeline configuration copied to clipboard!")

    def _copy_jenkinsfile(self):
        txt = self.cicd_jenkins_txt.toPlainText().strip()
        if not txt:
            QMessageBox.warning(self, "No Jenkinsfile", "No Jenkinsfile available to copy.")
            return
        QApplication.clipboard().setText(txt)
        QMessageBox.information(self, "Jenkinsfile Copied", "Jenkins Declarative Pipeline script copied to clipboard!")

    def _copy_junit_xml(self):
        txt = self.cicd_junit_txt.toPlainText().strip()
        if not txt:
            QMessageBox.warning(self, "No JUnit XML", "No JUnit XML test results available to copy.")
            return
        QApplication.clipboard().setText(txt)
        QMessageBox.information(self, "JUnit XML Copied", "Universal JUnit XML test results copied to clipboard!")

    def _export_github_workflow(self):
        report = getattr(self, "_current_cicd_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("cicd_report")
        if not report:
            QMessageBox.warning(self, "No CI/CD Report", "Please execute an audit or gate evaluation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save GitHub Actions Workflow", "quality_gate.yml", "YAML Files (*.yml *.yaml)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("github_actions_yaml", ""))
            QMessageBox.information(self, "Workflow Exported", f"GitHub Actions workflow saved to:\n{file_path}\n\nPlace inside `.github/workflows/` of your repository.")

    def _export_gitlab_pipeline(self):
        report = getattr(self, "_current_cicd_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("cicd_report")
        if not report:
            QMessageBox.warning(self, "No CI/CD Report", "Please execute an audit or gate evaluation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save GitLab CI Configuration", ".gitlab-ci.yml", "YAML Files (*.yml *.yaml)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("gitlab_ci_yaml", ""))
            QMessageBox.information(self, "Pipeline Exported", f"GitLab CI configuration saved to:\n{file_path}\n\nPlace in the root of your GitLab repository.")

    def _export_jenkinsfile(self):
        report = getattr(self, "_current_cicd_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("cicd_report")
        if not report:
            QMessageBox.warning(self, "No CI/CD Report", "Please execute an audit or gate evaluation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Jenkins Declarative Pipeline", "Jenkinsfile", "All Files (*)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("jenkinsfile_content", ""))
            QMessageBox.information(self, "Jenkinsfile Exported", f"Jenkinsfile saved to:\n{file_path}\n\nReady for Jenkins multibranch pipeline scan.")

    def _export_junit_xml(self):
        report = getattr(self, "_current_cicd_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("cicd_report")
        if not report:
            QMessageBox.warning(self, "No CI/CD Report", "Please execute an audit or gate evaluation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Universal JUnit XML Deliverable", "junit_results.xml", "XML Files (*.xml)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("junit_xml_content", ""))
            QMessageBox.information(self, "JUnit XML Exported", f"Universal JUnit XML results saved to:\n{file_path}\n\nCompatible with all CI/CD test visualizers.")

    def _export_cicd_html(self):
        report = getattr(self, "_current_cicd_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("cicd_report")
        if not report:
            QMessageBox.warning(self, "No CI/CD Report", "Please execute an audit or gate evaluation first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save CI/CD Quality Gate Deliverable HTML", "Quality_Gate_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_cicd_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional CI/CD Quality Gate Deliverable HTML saved to:\n{file_path}")

    # =========================================================================
    # DATABASE INTEGRITY & SCHEMA CONTROLLER METHODS
    # =========================================================================
    def _populate_db(self, result: ScanResult):
        target = result.target
        if not target:
            return

        db_data = target.metadata.get("database_report") if target.metadata else None
        if not db_data:
            try:
                db_data = DatabaseTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["database_report"] = db_data
            except Exception:
                db_data = None

        if not db_data:
            return

        self._current_db_report = db_data

        name = db_data.get("target_name", target.display_name)
        engine = db_data.get("database_engine", "Enterprise RDBMS")
        score = db_data.get("data_integrity_score", 100.0)
        status = db_data.get("overall_status", "PRODUCTION CERTIFIED")
        total_tbl = db_data.get("total_tables_checked", 0)
        total_chk = db_data.get("total_checks", 0)
        defects_cnt = db_data.get("defects_count", 0)
        warnings_cnt = db_data.get("warnings_count", 0)

        status_col = "#00ff9d" if "CERTIFIED" in status else "#ffb800" if "ATTENTION" in status else "#ff3366"

        self.db_target_lbl.setText(
            f"Target: {name}  |  Engine: {engine}  |  Score: {score:.1f}%  |  Status: {status}  |  Tables: {total_tbl}"
        )

        self.card_db_score.val_lbl.setText(f"{score:.1f}%")
        self.card_db_score.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {status_col};")
        self.card_db_tables.val_lbl.setText(str(total_tbl))
        self.card_db_checks.val_lbl.setText(str(total_chk))
        self.card_db_defects.val_lbl.setText(str(defects_cnt))
        self.card_db_defects.val_lbl.setStyleSheet(f"font-size: 17px; font-weight: 800; color: {'#00ff9d' if defects_cnt == 0 else '#ff2a44'};")
        self.card_db_warnings.val_lbl.setText(str(warnings_cnt))
        self.card_db_engine.val_lbl.setText(engine.split()[0])

        # Populate Tables Directory
        self.db_tables_table.setRowCount(0)
        for i, t in enumerate(db_data.get("tables", [])):
            self.db_tables_table.insertRow(i)
            item_name = QTableWidgetItem(t.get("table_name", ""))
            item_name.setForeground(QColor("#38bdf8"))
            item_cols = QTableWidgetItem(str(t.get("column_count", 0)))
            item_rows = QTableWidgetItem(f"{t.get('estimated_row_count', 0):,}")
            item_pk = QTableWidgetItem(t.get("primary_key", ""))
            unidx = ", ".join(t.get("unindexed_foreign_keys", [])) if t.get("unindexed_foreign_keys") else "None (Indexed)"
            item_unidx = QTableWidgetItem(unidx)
            item_unidx.setForeground(QColor("#ffb800" if t.get("unindexed_foreign_keys") else "#00ff9d"))

            self.db_tables_table.setItem(i, 0, item_name)
            self.db_tables_table.setItem(i, 1, item_cols)
            self.db_tables_table.setItem(i, 2, item_rows)
            self.db_tables_table.setItem(i, 3, item_pk)
            self.db_tables_table.setItem(i, 4, item_unidx)

        # Populate Defects Matrix
        self._populate_db_defects_table(db_data.get("defects", []))

        # Tabs content
        self.db_sql_txt.setText(db_data.get("ready_to_run_sql_migration", ""))
        self.db_deliverable_txt.setText(db_data.get("copiable_client_markdown", ""))

    def _populate_db_defects_table(self, defects: List[Dict[str, Any]]):
        self.db_defects_table.setRowCount(0)
        for i, d in enumerate(defects):
            self.db_defects_table.insertRow(i)
            item_id = QTableWidgetItem(d.get("defect_id", ""))
            item_id.setData(Qt.UserRole, d)
            item_cat = QTableWidgetItem(d.get("category", ""))
            sev = d.get("severity", "INFO")
            item_sev = QTableWidgetItem(sev)
            s_col = "#ff2a44" if sev == "CRITICAL" else "#f97316" if sev == "HIGH" else "#ffb800" if sev == "MEDIUM" else "#38bdf8"
            item_sev.setForeground(QColor(s_col))

            st = d.get("status", "PASSED")
            item_st = QTableWidgetItem(st)
            st_col = "#00ff9d" if st == "PASSED" else "#ff2a44" if st == "DEFECT" else "#ffb800"
            item_st.setForeground(QColor(st_col))

            item_title = QTableWidgetItem(d.get("title", ""))
            item_ent = QTableWidgetItem(d.get("target_entity", ""))

            self.db_defects_table.setItem(i, 0, item_id)
            self.db_defects_table.setItem(i, 1, item_cat)
            self.db_defects_table.setItem(i, 2, item_sev)
            self.db_defects_table.setItem(i, 3, item_st)
            self.db_defects_table.setItem(i, 4, item_title)
            self.db_defects_table.setItem(i, 5, item_ent)

        if defects:
            self.db_defects_table.selectRow(0)

    def _on_db_defect_selected(self):
        selected = self.db_defects_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        item = self.db_defects_table.item(row, 0)
        if not item:
            return
        d = item.data(Qt.UserRole)
        if not d:
            return

        self.db_insp_title.setText(f"[{d.get('defect_id')}] {d.get('title')} ({d.get('status')})")
        st_col = "#00ff9d" if d.get("status") == "PASSED" else "#ff2a44" if d.get("status") == "DEFECT" else "#ffb800"
        self.db_insp_title.setStyleSheet(f"font-size: 14px; font-weight: 800; color: {st_col};")
        self.db_insp_desc.setText(f"Description: {d.get('description', '')}")
        self.db_insp_impact.setText(f"Impact: {d.get('impact', '')}")
        self.db_insp_sql.setText(d.get("remediation_sql", "-- No remediation required."))

    def _filter_db_defects(self, filter_type: str):
        report = getattr(self, "_current_db_report", None)
        if not report:
            return
        all_defects = report.get("defects", [])
        if filter_type == "all":
            filtered = all_defects
        elif filter_type == "schema":
            filtered = [d for d in all_defects if "Schema" in d.get("category", "")]
        elif filter_type == "indexes":
            filtered = [d for d in all_defects if "Index" in d.get("category", "")]
        elif filter_type == "integrity":
            filtered = [d for d in all_defects if "Integrity" in d.get("category", "")]
        elif filter_type == "acid":
            filtered = [d for d in all_defects if "ACID" in d.get("category", "")]
        elif filter_type == "sqli":
            filtered = [d for d in all_defects if "SQL" in d.get("category", "")]
        else:
            filtered = all_defects
        self._populate_db_defects_table(filtered)

    def _rerun_db_audit(self):
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            target_str = self.target_path_edit.text().strip() or "https://pmec.ac.in"
            target_type = self._selected_target_type
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = DatabaseTester.run_tests(target, target.metadata, findings)
            target.metadata["database_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_db(self.current_result)
            QMessageBox.information(
                self, "Database Audit Complete",
                f"Database integrity audit finished for {target.display_name}!\n\n"
                f"Tables Inspected: {report.total_tables_checked}\n"
                f"Data Integrity Score: {report.data_integrity_score}%\n"
                f"Defects Found: {report.defects_count}\n"
                f"Certification Status: {report.overall_status}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Audit Error", f"Failed to execute database audit:\n{str(e)}")

    def _copy_db_markdown(self):
        md = self.db_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No database audit deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Corporate database audit deliverable copied to clipboard!")

    def _copy_db_sql(self):
        sql = self.db_sql_txt.toPlainText().strip()
        if not sql:
            QMessageBox.warning(self, "No SQL Patch", "No SQL migration patch available to copy.")
            return
        QApplication.clipboard().setText(sql)
        QMessageBox.information(self, "SQL Copied", "Idempotent DDL remediation SQL patch copied to clipboard!")

    def _export_db_sql(self):
        report = getattr(self, "_current_db_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("database_report")
        if not report:
            QMessageBox.warning(self, "No Database Report", "Please execute an audit first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Remediation SQL Patch", "database_migration_patch.sql", "SQL Files (*.sql)"
        )
        if file_path:
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(report.get("ready_to_run_sql_migration", ""))
            QMessageBox.information(self, "SQL Exported", f"Remediation SQL patch saved to:\n{file_path}\n\nReady to run in staging or production migration.")

    def _export_db_html(self):
        report = getattr(self, "_current_db_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("database_report")
        if not report:
            QMessageBox.warning(self, "No Database Report", "Please execute an audit first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Database Deliverable HTML Report", "Database_Integrity_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_database_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional Database Deliverable HTML saved to:\n{file_path}")

    # =========================================================================
    # COMPATIBILITY & MULTI-DEVICE VIEWPORT CONTROLLER METHODS
    # =========================================================================
    def _populate_compat(self, result: ScanResult):
        target = result.target
        if not target:
            return

        compat_data = target.metadata.get("compatibility_report") if target.metadata else None
        if not compat_data:
            try:
                compat_data = CompatibilityTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["compatibility_report"] = compat_data
            except Exception:
                compat_data = None

        if not compat_data:
            return

        self._current_compat_report = compat_data
        self.compat_target_lbl.setText(
            f"Target: {target.display_name} ({target.target_type.value.upper()}) | "
            f"Viewports: {compat_data.get('total_viewports_tested')} Form Factors | Status: {compat_data.get('overall_status')}"
        )

        score = compat_data.get("compatibility_score", 100.0)
        status = compat_data.get("overall_status", "WCAG AA CERTIFIED")
        status_col = "#00ff9d" if "CERTIFIED" in status else "#ffb800" if "WARNINGS" in status or "ATTENTION" in status else "#ff2a44"

        self.card_compat_score.val_lbl.setText(f"{score:.1f}%")
        self.card_compat_score.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 18px;")

        self.card_compat_viewports.val_lbl.setText(str(compat_data.get("total_viewports_tested", 0)))
        self.card_compat_checks.val_lbl.setText(str(compat_data.get("total_checks", 0)))
        self.card_compat_defects.val_lbl.setText(str(compat_data.get("defects_count", 0)))
        self.card_compat_warnings.val_lbl.setText(str(compat_data.get("warnings_count", 0)))

        self.card_compat_status.val_lbl.setText(status[:18])
        self.card_compat_status.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 12px;")

        # Populate Devices Table
        devices = compat_data.get("devices", [])
        self.compat_devices_table.setRowCount(len(devices))
        for r, dev in enumerate(devices):
            item_name = QTableWidgetItem(dev.get("name", ""))
            item_name.setForeground(QColor("#38bdf8"))
            item_cat = QTableWidgetItem(dev.get("category", ""))
            item_cat.setForeground(QColor("#8b9bb4"))
            dims = f"{dev.get('viewport_width')}x{dev.get('viewport_height')}"
            item_dims = QTableWidgetItem(dims)
            item_dpr = QTableWidgetItem(f"{dev.get('device_scale_factor')}x")

            dev_st = dev.get("status", "PASSED")
            item_st = QTableWidgetItem(f"[{dev_st}]")
            item_st.setForeground(QColor("#00ff9d" if dev_st == "PASSED" else "#ffb800" if dev_st == "WARNING" else "#ff3366"))

            over = "OVERFLOW" if dev.get("horizontal_overflow") else "Clean"
            item_over = QTableWidgetItem(over)
            item_over.setForeground(QColor("#ff3366" if dev.get("horizontal_overflow") else "#00ff9d"))

            item_tch = QTableWidgetItem(str(dev.get("touch_hazard_count", 0)))
            item_tch.setForeground(QColor("#00ff9d" if dev.get("touch_hazard_count", 0) == 0 else "#ff2a44"))

            for c, it in enumerate([item_name, item_cat, item_dims, item_dpr, item_st, item_over, item_tch]):
                self.compat_devices_table.setItem(r, c, it)

        # Store defects and populate defects table
        self._raw_compat_defects = compat_data.get("defects", [])
        self._populate_compat_defects_table()

        # Populate Script and Deliverable tabs
        self.compat_pw_txt.setPlainText(compat_data.get("playwright_matrix_script", ""))
        self.compat_cy_txt.setPlainText(compat_data.get("cypress_matrix_script", ""))
        self.compat_deliverable_txt.setPlainText(compat_data.get("copiable_client_markdown", ""))

    def _populate_compat_defects_table(self):
        defects = getattr(self, "_filtered_compat_defects", getattr(self, "_raw_compat_defects", []))
        self.compat_defects_table.setRowCount(len(defects))

        for r, d in enumerate(defects):
            item_id = QTableWidgetItem(d.get("defect_id", ""))
            item_id.setForeground(QColor("#38bdf8"))
            item_cat = QTableWidgetItem(d.get("category", ""))
            item_cat.setForeground(QColor("#cbd5e1"))

            sev = d.get("severity", "MEDIUM")
            item_sev = QTableWidgetItem(sev)
            item_sev.setForeground(QColor("#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"))

            st = d.get("status", "PASSED")
            item_st = QTableWidgetItem(f"[{st}]")
            item_st.setForeground(QColor("#00ff9d" if st == "PASSED" else "#ffb800" if st == "WARNING" else "#ff3366"))

            item_title = QTableWidgetItem(d.get("title", ""))
            item_vp = QTableWidgetItem(d.get("affected_viewport", ""))
            item_vp.setForeground(QColor("#8b9bb4"))

            for c, it in enumerate([item_id, item_cat, item_sev, item_st, item_title, item_vp]):
                self.compat_defects_table.setItem(r, c, it)

        if defects:
            self.compat_defects_table.selectRow(0)
            self._display_compat_defect_detail(defects[0])
        else:
            self.compat_insp_title.setText("Zero defects matched filter.")
            self.compat_insp_meta.setText("")
            self.compat_insp_desc.setText("")
            self.compat_insp_impact.setText("")
            self.compat_insp_code.clear()

    def _on_compat_defect_selected(self):
        selected = self.compat_defects_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        defects = getattr(self, "_filtered_compat_defects", getattr(self, "_raw_compat_defects", []))
        if 0 <= row < len(defects):
            self._display_compat_defect_detail(defects[row])

    def _display_compat_defect_detail(self, d: Dict[str, Any]):
        sev = d.get("severity", "MEDIUM")
        status = d.get("status", "PASSED")
        sev_col = "#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"

        self.compat_insp_title.setText(f"{d.get('title')} [{d.get('defect_id')}]")
        self.compat_insp_meta.setText(f"Severity: {sev} | Status: [{status}] | Criterion: {d.get('wcag_criterion')} | Viewports: {d.get('affected_viewport')}")
        self.compat_insp_meta.setStyleSheet(f"font-size: 12px; color: {sev_col}; font-weight: 700;")
        self.compat_insp_desc.setText(f"Description: {d.get('description')}")
        self.compat_insp_impact.setText(f"Impact: {d.get('impact')}")
        self.compat_insp_code.setPlainText(d.get("remediation_code", ""))

    def _filter_compat_defects(self, fltr_type: str):
        raw = getattr(self, "_raw_compat_defects", [])
        if fltr_type == "layout":
            self._filtered_compat_defects = [d for d in raw if "Layout" in d.get("category", "") or "Reflow" in d.get("category", "")]
        elif fltr_type == "touch":
            self._filtered_compat_defects = [d for d in raw if "Touch" in d.get("category", "")]
        elif fltr_type == "contrast":
            self._filtered_compat_defects = [d for d in raw if "Contrast" in d.get("category", "")]
        elif fltr_type == "forms":
            self._filtered_compat_defects = [d for d in raw if "Form" in d.get("category", "")]
        elif fltr_type == "defects_only":
            self._filtered_compat_defects = [d for d in raw if d.get("status") in ("DEFECT", "WARNING")]
        else:
            self._filtered_compat_defects = list(raw)
        self._populate_compat_defects_table()

    def _rerun_compat_audit(self):
        target_str = self.target_path_edit.text().strip()
        if not target_str:
            QMessageBox.warning(self, "Missing Target", "Please enter a valid target URL or path.")
            return

        target_type = self._selected_target_type
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = CompatibilityTester.run_tests(target, target.metadata, findings)
            target.metadata["compatibility_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_compat(self.current_result)
            QMessageBox.information(
                self, "Compatibility Audit Complete",
                f"Multi-device responsive & WCAG audit finished for {target.display_name}!\n\n"
                f"Viewports Audited: {report.total_viewports_tested}\n"
                f"Compatibility Score: {report.compatibility_score}%\n"
                f"Defects Found: {report.defects_count}\n"
                f"Certification Status: {report.overall_status}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Audit Error", f"Failed to execute compatibility audit:\n{str(e)}")

    def _copy_compat_markdown(self):
        md = self.compat_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No compatibility deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Corporate compatibility & WCAG deliverable copied to clipboard!")

    def _copy_compat_playwright(self):
        pw = self.compat_pw_txt.toPlainText().strip()
        if not pw:
            QMessageBox.warning(self, "No Script", "No Playwright matrix test script available to copy.")
            return
        QApplication.clipboard().setText(pw)
        QMessageBox.information(self, "Script Copied", "Playwright multi-device matrix test script copied to clipboard!")

    def _copy_compat_cypress(self):
        cy = self.compat_cy_txt.toPlainText().strip()
        if not cy:
            QMessageBox.warning(self, "No Script", "No Cypress reflow test script available to copy.")
            return
        QApplication.clipboard().setText(cy)
        QMessageBox.information(self, "Script Copied", "Cypress multi-device viewport reflow script copied to clipboard!")

    def _export_compat_html(self):
        report = getattr(self, "_current_compat_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("compatibility_report")
        if not report:
            QMessageBox.warning(self, "No Compatibility Report", "Please execute an audit first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Compatibility & A11y Deliverable HTML", "Compatibility_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_compatibility_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional Compatibility & WCAG Deliverable HTML saved to:\n{file_path}")

    # =========================================================================
    # NETWORK PROTOCOL, TLS CIPHERS & CERTIFICATE CONTROLLER METHODS
    # =========================================================================
    def _populate_network(self, result: ScanResult):
        target = result.target
        if not target:
            return

        net_data = target.metadata.get("network_report") if target.metadata else None
        if not net_data:
            try:
                net_data = NetworkTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["network_report"] = net_data
            except Exception:
                net_data = None

        if not net_data:
            return

        self._current_net_report = net_data
        self.net_target_lbl.setText(
            f"Target: {target.display_name} ({net_data.get('target_host')}:{net_data.get('port')}) | "
            f"TLS Grade: GRADE {net_data.get('tls_grade')} | Status: {net_data.get('overall_status')}"
        )

        score = net_data.get("crypto_score", 100.0)
        grade = net_data.get("tls_grade", "A")
        status = net_data.get("overall_status", "ENTERPRISE HARDENED")
        status_col = "#00ff9d" if "HARDENED" in status else "#ffb800" if "ATTENTION" in status else "#ff2a44"

        cipher = net_data.get("cipher_info") or {}
        cert = net_data.get("cert_info") or {}
        dns_mail = net_data.get("dns_mail_info") or {}

        self.card_net_score.val_lbl.setText(f"{score:.1f}%")
        self.card_net_score.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 18px;")

        self.card_net_grade.val_lbl.setText(f"GRADE {grade}")
        self.card_net_grade.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 15px;")

        self.card_net_protocol.val_lbl.setText(cipher.get("protocol_version", "TLSv1.3"))
        self.card_net_cert_days.val_lbl.setText(f"{cert.get('days_to_expiration', 0)}d Left")
        self.card_net_defects.val_lbl.setText(str(net_data.get("defects_count", 0)))
        self.card_net_warnings.val_lbl.setText(str(net_data.get("warnings_count", 0)))

        # Populate Telemetry Table
        telemetry_rows = [
            ("Negotiated TLS Protocol", cipher.get("protocol_version", "TLSv1.3")),
            ("Active Cipher Suite", cipher.get("cipher_suite", "TLS_AES_256_GCM_SHA384")),
            ("Key Exchange Mechanism", cipher.get("key_exchange", "ECDHE (Curve X25519)")),
            ("Encryption & MAC Mode", cipher.get("encryption_algorithm", "AES-256-GCM (AEAD)")),
            ("Perfect Forward Secrecy", "ENABLED (Curve X25519)" if cipher.get("perfect_forward_secrecy") else "DISABLED"),
            ("X.509 Common Name (CN)", cert.get("common_name", "")),
            ("Certificate Issuer", cert.get("issuer_org", "")),
            ("Validity Expiration", f"{cert.get('valid_until', '')} ({cert.get('days_to_expiration', 0)}d left)"),
            ("Public Key Algorithm", f"{cert.get('key_type_and_bits', 'RSA 2048-bit')} ({cert.get('signature_algorithm', '')})"),
            ("OCSP Stapling Proof", "ENABLED (Optimal)" if cert.get("ocsp_stapling") else "OMITTED (Warning)"),
            ("ALPN HTTP/2 Protocol", "YES (h2 Negotiated)" if dns_mail.get("alpn_http2_supported") else "NO"),
            ("DNS CAA Records", "Configured (Authorized)" if dns_mail.get("caa_records_present") else "MISSING (Defect)"),
            ("Anti-Spoof DMARC Policy", dns_mail.get("dmarc_policy", "MISSING")),
        ]

        self.net_telemetry_table.setRowCount(len(telemetry_rows))
        for r, (attr, val) in enumerate(telemetry_rows):
            it_attr = QTableWidgetItem(attr)
            it_attr.setForeground(QColor("#cbd5e1"))
            it_val = QTableWidgetItem(val)
            if "ENABLED" in val or "YES" in val or "Configured" in val:
                it_val.setForeground(QColor("#00ff9d"))
            elif "DISABLED" in val or "MISSING" in val or "OMITTED" in val:
                it_val.setForeground(QColor("#ffb800" if "OMITTED" in val else "#ff2a44"))
            else:
                it_val.setForeground(QColor("#38bdf8"))
            self.net_telemetry_table.setItem(r, 0, it_attr)
            self.net_telemetry_table.setItem(r, 1, it_val)

        # Store defects and populate defects table
        self._raw_net_defects = net_data.get("defects", [])
        self._populate_net_defects_table()

        # Populate Script and Deliverable tabs
        self.net_openssl_txt.setPlainText(net_data.get("openssl_diagnostic_script", ""))
        self.net_deliverable_txt.setPlainText(net_data.get("copiable_client_markdown", ""))

    def _populate_net_defects_table(self):
        defects = getattr(self, "_filtered_net_defects", getattr(self, "_raw_net_defects", []))
        self.net_defects_table.setRowCount(len(defects))

        for r, d in enumerate(defects):
            item_id = QTableWidgetItem(d.get("defect_id", ""))
            item_id.setForeground(QColor("#38bdf8"))
            item_cat = QTableWidgetItem(d.get("category", ""))
            item_cat.setForeground(QColor("#cbd5e1"))

            sev = d.get("severity", "MEDIUM")
            item_sev = QTableWidgetItem(sev)
            item_sev.setForeground(QColor("#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"))

            st = d.get("status", "PASSED")
            item_st = QTableWidgetItem(f"[{st}]")
            item_st.setForeground(QColor("#00ff9d" if st == "PASSED" else "#ffb800" if st == "WARNING" else "#ff3366"))

            item_title = QTableWidgetItem(d.get("title", ""))
            item_comp = QTableWidgetItem(d.get("target_component", ""))
            item_comp.setForeground(QColor("#8b9bb4"))

            for c, it in enumerate([item_id, item_cat, item_sev, item_st, item_title, item_comp]):
                self.net_defects_table.setItem(r, c, it)

        if defects:
            self.net_defects_table.selectRow(0)
            self._display_net_defect_detail(defects[0])
        else:
            self.net_insp_title.setText("Zero defects matched filter.")
            self.net_insp_meta.setText("")
            self.net_insp_desc.setText("")
            self.net_insp_impact.setText("")
            self.net_insp_code.clear()

    def _on_net_defect_selected(self):
        selected = self.net_defects_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        defects = getattr(self, "_filtered_net_defects", getattr(self, "_raw_net_defects", []))
        if 0 <= row < len(defects):
            self._display_net_defect_detail(defects[row])

    def _display_net_defect_detail(self, d: Dict[str, Any]):
        sev = d.get("severity", "MEDIUM")
        status = d.get("status", "PASSED")
        sev_col = "#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"

        self.net_insp_title.setText(f"{d.get('title')} [{d.get('defect_id')}]")
        self.net_insp_meta.setText(f"Severity: {sev} | Status: [{status}] | Component: {d.get('target_component')} | Category: {d.get('category')}")
        self.net_insp_meta.setStyleSheet(f"font-size: 12px; color: {sev_col}; font-weight: 700;")
        self.net_insp_desc.setText(f"Description: {d.get('description')}")
        self.net_insp_impact.setText(f"Impact: {d.get('impact')}")
        self.net_insp_code.setPlainText(d.get("remediation_config", ""))

    def _filter_net_defects(self, fltr_type: str):
        raw = getattr(self, "_raw_net_defects", [])
        if fltr_type == "protocol":
            self._filtered_net_defects = [d for d in raw if "Protocol" in d.get("category", "")]
        elif fltr_type == "ciphers":
            self._filtered_net_defects = [d for d in raw if "Cipher" in d.get("category", "")]
        elif fltr_type == "cert":
            self._filtered_net_defects = [d for d in raw if "Cert" in d.get("category", "")]
        elif fltr_type == "dns":
            self._filtered_net_defects = [d for d in raw if "DNS" in d.get("category", "") or "Spoof" in d.get("category", "")]
        elif fltr_type == "defects_only":
            self._filtered_net_defects = [d for d in raw if d.get("status") in ("DEFECT", "WARNING")]
        else:
            self._filtered_net_defects = list(raw)
        self._populate_net_defects_table()

    def _rerun_net_audit(self):
        target_str = self.target_path_edit.text().strip()
        if not target_str:
            QMessageBox.warning(self, "Missing Target", "Please enter a valid target URL or host.")
            return

        target_type = self._selected_target_type
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = NetworkTester.run_tests(target, target.metadata, findings)
            target.metadata["network_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_network(self.current_result)
            QMessageBox.information(
                self, "Network Audit Complete",
                f"Network & TLS protocol audit finished for {target.display_name}!\n\n"
                f"TLS Health Grade: GRADE {report.tls_grade}\n"
                f"Cryptographic Score: {report.crypto_score}%\n"
                f"Defects Found: {report.defects_count}\n"
                f"Certification Status: {report.overall_status}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Audit Error", f"Failed to execute network audit:\n{str(e)}")

    def _copy_net_markdown(self):
        md = self.net_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No network/TLS deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Corporate TLS & network security deliverable copied to clipboard!")

    def _copy_openssl_script(self):
        script = self.net_openssl_txt.toPlainText().strip()
        if not script:
            QMessageBox.warning(self, "No Script", "No OpenSSL diagnostic script available to copy.")
            return
        QApplication.clipboard().setText(script)
        QMessageBox.information(self, "Script Copied", "OpenSSL diagnostic shell script copied to clipboard!")

    def _export_net_html(self):
        report = getattr(self, "_current_net_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("network_report")
        if not report:
            QMessageBox.warning(self, "No Network Report", "Please execute an audit first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Network & TLS Deliverable HTML", "Network_TLS_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_network_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional Network & TLS Deliverable HTML saved to:\n{file_path}")

    # =========================================================================
    # BUSINESS LOGIC, STATE MACHINE & WORKFLOW INTEGRITY CONTROLLER METHODS
    # =========================================================================
    def _populate_logic(self, result: ScanResult):
        target = result.target
        if not target:
            return

        logic_data = target.metadata.get("business_logic_report") if target.metadata else None
        if not logic_data:
            try:
                logic_data = BusinessLogicTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["business_logic_report"] = logic_data
            except Exception:
                logic_data = None

        if not logic_data:
            return

        self._current_logic_report = logic_data
        score = logic_data.get("logic_integrity_score", 100.0)
        status = logic_data.get("overall_status", "LOGIC HARDENED")
        status_col = "#00ff9d" if "HARDENED" in status else "#ffb800" if "ATTENTION" in status else "#ff2a44"

        self.logic_target_lbl.setText(
            f"Target: {target.display_name} | Score: {score:.1f}% | "
            f"Evaluated Workflows: {logic_data.get('total_workflows_evaluated', 0)} | Status: {status}"
        )

        self.card_logic_score.val_lbl.setText(f"{score:.1f}%")
        self.card_logic_score.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 18px;")

        self.card_logic_status.val_lbl.setText(status[:20])
        self.card_logic_status.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 12px;")

        self.card_logic_workflows.val_lbl.setText(str(logic_data.get("total_workflows_evaluated", 0)))
        self.card_logic_checks.val_lbl.setText(str(logic_data.get("total_checks", 0)))
        self.card_logic_defects.val_lbl.setText(str(logic_data.get("defects_count", 0)))
        self.card_logic_warnings.val_lbl.setText(str(logic_data.get("warnings_count", 0)))

        # Populate Workflows Table
        workflows = logic_data.get("workflows", [])
        self.logic_workflows_table.setRowCount(len(workflows))
        for r, wf in enumerate(workflows):
            it_wf = QTableWidgetItem(f"✓  {wf}")
            it_wf.setForeground(QColor("#a855f7"))
            self.logic_workflows_table.setItem(r, 0, it_wf)

        # Store flaws and populate defect table
        self._raw_logic_defects = logic_data.get("flaws", [])
        self._populate_logic_defects_table()

        # Populate Pytest and Deliverable tabs
        self.logic_pytest_txt.setPlainText(logic_data.get("pytest_logic_suite", ""))
        self.logic_deliverable_txt.setPlainText(logic_data.get("copiable_client_markdown", ""))

    def _populate_logic_defects_table(self):
        flaws = getattr(self, "_filtered_logic_defects", getattr(self, "_raw_logic_defects", []))
        self.logic_defects_table.setRowCount(len(flaws))

        for r, f in enumerate(flaws):
            item_id = QTableWidgetItem(f.get("flaw_id", ""))
            item_id.setForeground(QColor("#a855f7"))
            item_cat = QTableWidgetItem(f.get("category", ""))
            item_cat.setForeground(QColor("#cbd5e1"))

            sev = f.get("severity", "MEDIUM")
            item_sev = QTableWidgetItem(sev)
            item_sev.setForeground(QColor("#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"))

            st = f.get("status", "PASSED")
            item_st = QTableWidgetItem(f"[{st}]")
            item_st.setForeground(QColor("#00ff9d" if st == "PASSED" else "#ffb800" if st == "WARNING" else "#ff3366"))

            item_title = QTableWidgetItem(f.get("title", ""))
            item_wf = QTableWidgetItem(f.get("target_workflow", ""))
            item_wf.setForeground(QColor("#8b9bb4"))

            for c, it in enumerate([item_id, item_cat, item_sev, item_st, item_title, item_wf]):
                self.logic_defects_table.setItem(r, c, it)

        if flaws:
            self.logic_defects_table.selectRow(0)
            self._display_logic_defect_detail(flaws[0])
        else:
            self.logic_insp_title.setText("Zero business logic flaws matched filter.")
            self.logic_insp_meta.setText("")
            self.logic_insp_desc.setText("")
            self.logic_insp_impact.setText("")
            self.logic_insp_poc.clear()
            self.logic_insp_remed.clear()

    def _on_logic_defect_selected(self):
        selected = self.logic_defects_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        flaws = getattr(self, "_filtered_logic_defects", getattr(self, "_raw_logic_defects", []))
        if 0 <= row < len(flaws):
            self._display_logic_defect_detail(flaws[row])

    def _display_logic_defect_detail(self, f: Dict[str, Any]):
        sev = f.get("severity", "MEDIUM")
        status = f.get("status", "PASSED")
        sev_col = "#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"

        self.logic_insp_title.setText(f"{f.get('title')} [{f.get('flaw_id')}]")
        self.logic_insp_meta.setText(f"Workflow: {f.get('target_workflow')} | Category: {f.get('category')} | Status: [{status}]")
        self.logic_insp_meta.setStyleSheet(f"font-size: 12px; color: {sev_col}; font-weight: 700;")
        self.logic_insp_desc.setText(f"Description: {f.get('description')}")
        self.logic_insp_impact.setText(f"Exploit Impact: {f.get('impact')}")
        self.logic_insp_poc.setPlainText(f.get("flawed_sequence_poc", ""))
        self.logic_insp_remed.setPlainText(f.get("remediation_pattern", ""))

    def _filter_logic_defects(self, fltr_type: str):
        raw = getattr(self, "_raw_logic_defects", [])
        if fltr_type == "price":
            self._filtered_logic_defects = [d for d in raw if "Price" in d.get("category", "") or "Quantity" in d.get("category", "")]
        elif fltr_type == "sequence":
            self._filtered_logic_defects = [d for d in raw if "Sequence" in d.get("category", "") or "State" in d.get("category", "")]
        elif fltr_type == "privilege":
            self._filtered_logic_defects = [d for d in raw if "Privilege" in d.get("category", "") or "Access" in d.get("category", "")]
        elif fltr_type == "concurrency":
            self._filtered_logic_defects = [d for d in raw if "Concurrency" in d.get("category", "") or "Double-Spend" in d.get("category", "")]
        elif fltr_type == "mfa":
            self._filtered_logic_defects = [d for d in raw if "MFA" in d.get("category", "") or "Verification" in d.get("category", "")]
        elif fltr_type == "defects_only":
            self._filtered_logic_defects = [d for d in raw if d.get("status") in ("DEFECT", "WARNING")]
        else:
            self._filtered_logic_defects = list(raw)
        self._populate_logic_defects_table()

    def _rerun_logic_audit(self):
        target_str = self.target_path_edit.text().strip()
        if not target_str:
            QMessageBox.warning(self, "Missing Target", "Please enter a valid target URL or file path.")
            return

        target_type = self._selected_target_type
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = BusinessLogicTester.run_tests(target, target.metadata, findings)
            target.metadata["business_logic_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_logic(self.current_result)
            QMessageBox.information(
                self, "Business Logic Audit Complete",
                f"Business logic & workflow integrity audit finished for {target.display_name}!\n\n"
                f"Integrity Score: {report.logic_integrity_score}%\n"
                f"Status: {report.overall_status}\n"
                f"Workflows Evaluated: {report.total_workflows_evaluated}\n"
                f"Logic Defects Found: {report.defects_count}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Audit Error", f"Failed to execute business logic audit:\n{str(e)}")

    def _copy_logic_markdown(self):
        md = self.logic_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No business logic deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Executive Business Logic Deliverable copied to clipboard!")

    def _copy_pytest_logic(self):
        script = self.logic_pytest_txt.toPlainText().strip()
        if not script:
            QMessageBox.warning(self, "No Script", "No Pytest logic suite script available to copy.")
            return
        QApplication.clipboard().setText(script)
        QMessageBox.information(self, "Script Copied", "Automated Pytest business logic test suite copied to clipboard!")

    def _export_logic_html(self):
        report = getattr(self, "_current_logic_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("business_logic_report")
        if not report:
            QMessageBox.warning(self, "No Business Logic Report", "Please execute an audit first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Business Logic Deliverable HTML", "Business_Logic_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_business_logic_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional Business Logic Deliverable HTML saved to:\n{file_path}")

    # =========================================================================
    # MEMORY LEAK, OS HANDLE & RESOURCE EXHAUSTION CONTROLLER METHODS
    # =========================================================================
    def _populate_memory(self, result: ScanResult):
        target = result.target
        if not target:
            return

        mem_data = target.metadata.get("memory_report") if target.metadata else None
        if not mem_data:
            try:
                mem_data = MemoryLeakTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["memory_report"] = mem_data
            except Exception:
                mem_data = None

        if not mem_data:
            return

        self._current_mem_report = mem_data
        score = mem_data.get("memory_stability_score", 100.0)
        status = mem_data.get("overall_status", "MEMORY STABLE & HARDENED")
        status_col = "#00ff9d" if "STABLE" in status else "#ffb800" if "WARNING" in status or "DRIFT" in status else "#ff2a44"

        metrics = mem_data.get("metrics", {})
        init_mb = metrics.get("initial_memory_mb", 0.0)
        peak_mb = metrics.get("peak_working_set_mb", 0.0)
        delta_mb = metrics.get("memory_growth_delta_mb", 0.0)
        post_gc_mb = metrics.get("post_gc_retained_mb", 0.0)
        act_hnd = metrics.get("active_handle_count", 0)
        peak_hnd = metrics.get("peak_handle_count", 0)
        gdi_cnt = metrics.get("gdi_objects_count", 0)
        detached_cnt = metrics.get("detached_nodes_or_contexts", 0)
        leak_rate = metrics.get("projected_leak_rate_mb_hr", 0.0)

        self.mem_target_lbl.setText(
            f"Target: {target.display_name} | Score: {score:.1f}% | "
            f"RAM: {init_mb:.1f}MB -> {peak_mb:.1f}MB (+{delta_mb:.1f}MB) | Handles: {act_hnd}/{peak_hnd} | Status: {status}"
        )

        self.card_mem_score.val_lbl.setText(f"{score:.1f}%")
        self.card_mem_score.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 18px;")

        self.card_mem_status.val_lbl.setText(status[:20])
        self.card_mem_status.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 12px;")

        self.card_mem_peak.val_lbl.setText(f"{peak_mb:.1f} MB")
        self.card_mem_delta.val_lbl.setText(f"+{delta_mb:.1f} MB")
        self.card_mem_handles.val_lbl.setText(str(peak_hnd))
        self.card_mem_defects.val_lbl.setText(str(mem_data.get("defects_count", 0)))

        # Populate Telemetry Table
        telemetry_rows = [
            ("Initial Process Working Set (RAM)", f"{init_mb:.2f} MB (Baseline at startup)"),
            ("Peak Working Set Under Loop Stress", f"{peak_mb:.2f} MB (+{delta_mb:.2f} MB dynamic drift)"),
            ("Post-Garbage Collection Retained RAM", f"{post_gc_mb:.2f} MB (Unreclaimed heap)"),
            ("Active OS Kernel Handles", f"{act_hnd} handles (Files, Sockets, Threads)"),
            ("Peak OS Kernel Handles (Cap: 10,000)", f"{peak_hnd} handles allocated"),
            ("GDI Objects / Detached DOM Nodes", f"{gdi_cnt if target.target_type == TargetType.EXE else detached_cnt} active references"),
            ("Calculated Continuous Leak Rate", f"+{leak_rate:.2f} MB/hr continuous load"),
        ]

        self.mem_telemetry_table.setRowCount(len(telemetry_rows))
        for r, (attr, val) in enumerate(telemetry_rows):
            it_attr = QTableWidgetItem(attr)
            it_attr.setForeground(QColor("#cbd5e1"))
            it_val = QTableWidgetItem(val)
            if "Baseline" in val or "0.00" in val:
                it_val.setForeground(QColor("#00ff9d"))
            elif "drift" in val or "handles" in val or "references" in val:
                it_val.setForeground(QColor("#ffb800"))
            else:
                it_val.setForeground(QColor("#38bdf8"))
            self.mem_telemetry_table.setItem(r, 0, it_attr)
            self.mem_telemetry_table.setItem(r, 1, it_val)

        # Store defects and populate defects table
        self._raw_mem_defects = mem_data.get("defects", [])
        self._populate_mem_defects_table()

        # Populate Script and Deliverable tabs
        self.mem_script_txt.setPlainText(mem_data.get("diagnostic_script", ""))
        self.mem_deliverable_txt.setPlainText(mem_data.get("copiable_client_markdown", ""))

    def _populate_mem_defects_table(self):
        defects = getattr(self, "_filtered_mem_defects", getattr(self, "_raw_mem_defects", []))
        self.mem_defects_table.setRowCount(len(defects))

        for r, d in enumerate(defects):
            item_id = QTableWidgetItem(d.get("defect_id", ""))
            item_id.setForeground(QColor("#a855f7"))
            item_cat = QTableWidgetItem(d.get("category", ""))
            item_cat.setForeground(QColor("#cbd5e1"))

            sev = d.get("severity", "MEDIUM")
            item_sev = QTableWidgetItem(sev)
            item_sev.setForeground(QColor("#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"))

            st = d.get("status", "PASSED")
            item_st = QTableWidgetItem(f"[{st}]")
            item_st.setForeground(QColor("#00ff9d" if st == "PASSED" else "#ffb800" if st == "WARNING" else "#ff3366"))

            item_title = QTableWidgetItem(d.get("title", ""))
            item_comp = QTableWidgetItem(d.get("target_component", ""))
            item_comp.setForeground(QColor("#8b9bb4"))

            for c, it in enumerate([item_id, item_cat, item_sev, item_st, item_title, item_comp]):
                self.mem_defects_table.setItem(r, c, it)

        if defects:
            self.mem_defects_table.selectRow(0)
            self._display_mem_defect_detail(defects[0])
        else:
            self.mem_insp_title.setText("Zero memory defects matched filter.")
            self.mem_insp_meta.setText("")
            self.mem_insp_desc.setText("")
            self.mem_insp_impact.setText("")
            self.mem_insp_poc.clear()
            self.mem_insp_remed.clear()

    def _on_mem_defect_selected(self):
        selected = self.mem_defects_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        defects = getattr(self, "_filtered_mem_defects", getattr(self, "_raw_mem_defects", []))
        if 0 <= row < len(defects):
            self._display_mem_defect_detail(defects[row])

    def _display_mem_defect_detail(self, d: Dict[str, Any]):
        sev = d.get("severity", "MEDIUM")
        status = d.get("status", "PASSED")
        sev_col = "#ff3366" if sev in ("CRITICAL", "HIGH") else "#ffb800" if sev == "MEDIUM" else "#00d4ff"

        self.mem_insp_title.setText(f"{d.get('title')} [{d.get('defect_id')}]")
        self.mem_insp_meta.setText(f"Component: {d.get('target_component')} | Category: {d.get('category')} | Leak Rate: {d.get('leak_rate')}")
        self.mem_insp_meta.setStyleSheet(f"font-size: 12px; color: {sev_col}; font-weight: 700;")
        self.mem_insp_desc.setText(f"Description: {d.get('description')}")
        self.mem_insp_impact.setText(f"Exhaustion Impact: {d.get('impact')}")
        self.mem_insp_poc.setPlainText(d.get("diagnostic_poc", ""))
        self.mem_insp_remed.setPlainText(d.get("remediation_pattern", ""))

    def _filter_mem_defects(self, fltr_type: str):
        raw = getattr(self, "_raw_mem_defects", [])
        if fltr_type == "heap":
            self._filtered_mem_defects = [d for d in raw if "Heap" in d.get("category", "") or "Working" in d.get("category", "")]
        elif fltr_type == "handles":
            self._filtered_mem_defects = [d for d in raw if "Handle" in d.get("category", "") or "Exhaustion" in d.get("category", "")]
        elif fltr_type == "gdi":
            self._filtered_mem_defects = [d for d in raw if "GDI" in d.get("category", "")]
        elif fltr_type == "detached":
            self._filtered_mem_defects = [d for d in raw if "Detached" in d.get("category", "") or "Context" in d.get("category", "")]
        elif fltr_type == "defects_only":
            self._filtered_mem_defects = [d for d in raw if d.get("status") in ("DEFECT", "WARNING")]
        else:
            self._filtered_mem_defects = list(raw)
        self._populate_mem_defects_table()

    def _rerun_mem_audit(self):
        target_str = self.target_path_edit.text().strip()
        if not target_str:
            QMessageBox.warning(self, "Missing Target", "Please enter a valid target URL or file path.")
            return

        target_type = self._selected_target_type
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = MemoryLeakTester.run_tests(target, target.metadata, findings)
            target.metadata["memory_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_memory(self.current_result)
            QMessageBox.information(
                self, "Memory Profiling Complete",
                f"Memory leak & resource exhaustion audit finished for {target.display_name}!\n\n"
                f"Stability Score: {report.memory_stability_score}%\n"
                f"Status: {report.overall_status}\n"
                f"Peak Working Set: {report.metrics.peak_working_set_mb:.1f} MB (Delta: +{report.metrics.memory_growth_delta_mb:.1f} MB)\n"
                f"Peak Handles: {report.metrics.peak_handle_count}\n"
                f"Memory Defects Found: {report.defects_count}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Audit Error", f"Failed to execute memory audit:\n{str(e)}")

    def _copy_mem_markdown(self):
        md = self.mem_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No memory deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Executive Memory & Resource Deliverable copied to clipboard!")

    def _copy_leak_script(self):
        script = self.mem_script_txt.toPlainText().strip()
        if not script:
            QMessageBox.warning(self, "No Script", "No memory diagnostic script available to copy.")
            return
        QApplication.clipboard().setText(script)
        QMessageBox.information(self, "Script Copied", "Memory & Handle Stress Profiler script copied to clipboard!")

    def _export_mem_html(self):
        report = getattr(self, "_current_mem_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("memory_report")
        if not report:
            QMessageBox.warning(self, "No Memory Report", "Please execute an audit first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Memory Deliverable HTML", "Memory_Resource_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_memory_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional Memory & Resource Deliverable HTML saved to:\n{file_path}")

    # =========================================================================
    # ACCESSIBILITY & ASSISTIVE TECHNOLOGY (WCAG 2.2 / VPAT) CONTROLLER METHODS
    # =========================================================================
    def _populate_a11y(self, result: ScanResult):
        target = result.target
        if not target:
            return

        a11y_data = target.metadata.get("accessibility_report") if target.metadata else None
        if not a11y_data:
            try:
                a11y_data = AccessibilityTester.run_tests(target, target.metadata, result.findings).to_dict()
                target.metadata["accessibility_report"] = a11y_data
            except Exception:
                a11y_data = None

        if not a11y_data:
            return

        self._current_a11y_report = a11y_data
        metrics = a11y_data.get("metrics", {})
        score = metrics.get("wcag_score", 100.0)
        status = metrics.get("conformance_status", "CONFORMS (WCAG 2.2 AA)")
        status_col = "#00ff9d" if "CONFORMS" in status else "#ffb800" if "PARTIAL" in status else "#ff2a44"

        self.a11y_target_lbl.setText(
            f"Target: {target.display_name} | WCAG Score: {score:.1f}% | "
            f"Criteria: {metrics.get('total_criteria_checked', 0)} (Passed: {metrics.get('passed_criteria', 0)} | Defects: {metrics.get('defects_count', 0)}) | Status: {status}"
        )

        self.card_a11y_score.val_lbl.setText(f"{score:.1f}%")
        self.card_a11y_score.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 18px;")

        self.card_a11y_status.val_lbl.setText(status[:20])
        self.card_a11y_status.val_lbl.setStyleSheet(f"color: {status_col}; font-weight: 800; font-size: 12px;")

        self.card_a11y_checked.val_lbl.setText(str(metrics.get("total_criteria_checked", 0)))
        self.card_a11y_passed.val_lbl.setText(str(metrics.get("passed_criteria", 0)))
        self.card_a11y_defects.val_lbl.setText(str(metrics.get("defects_count", 0)))
        self.card_a11y_contrast.val_lbl.setText(str(metrics.get("contrast_violations", 0)))

        # Populate ARIA Landmarks Table
        landmarks = a11y_data.get("landmarks", [])
        self.a11y_landmarks_table.setRowCount(len(landmarks))
        for r, lm in enumerate(landmarks):
            it_role = QTableWidgetItem(lm.get("role", ""))
            it_role.setForeground(QColor("#38bdf8"))
            it_elem = QTableWidgetItem(lm.get("element", ""))
            it_elem.setForeground(QColor("#a7f3d0"))
            it_name = QTableWidgetItem(lm.get("accessible_name", ""))
            it_name.setForeground(QColor("#f0f4fc"))
            it_st = QTableWidgetItem(f"[{lm.get('status', 'VALID')}]")
            it_st.setForeground(QColor("#00ff9d" if lm.get("status") == "VALID" else "#ffb800"))

            for c, it in enumerate([it_role, it_elem, it_name, it_st]):
                self.a11y_landmarks_table.setItem(r, c, it)

        # Store defects and populate defects table
        self._raw_a11y_defects = a11y_data.get("defects", [])
        self._populate_a11y_defects_table()

        # Populate Script and Deliverable tabs
        self.a11y_axe_txt.setPlainText(a11y_data.get("axe_playwright_suite", ""))
        self.a11y_deliverable_txt.setPlainText(a11y_data.get("copiable_vpat_markdown", ""))

    def _populate_a11y_defects_table(self):
        defects = getattr(self, "_filtered_a11y_defects", getattr(self, "_raw_a11y_defects", []))
        self.a11y_defects_table.setRowCount(len(defects))

        for r, d in enumerate(defects):
            item_id = QTableWidgetItem(d.get("defect_id", ""))
            item_id.setForeground(QColor("#38bdf8"))

            item_sc = QTableWidgetItem(d.get("wcag_sc", ""))
            item_sc.setForeground(QColor("#cbd5e1"))

            item_lvl = QTableWidgetItem(f"Level {d.get('level', 'AA')}")
            item_lvl.setForeground(QColor("#38bdf8"))

            st = d.get("status", "PASSED")
            item_st = QTableWidgetItem(f"[{st}]")
            item_st.setForeground(QColor("#00ff9d" if st == "PASSED" else "#ffb800" if st == "WARNING" else "#ff3366"))

            item_title = QTableWidgetItem(d.get("title", ""))

            vpat = d.get("vpat_conformance", "Supports")
            item_vpat = QTableWidgetItem(vpat)
            item_vpat.setForeground(QColor("#00ff9d" if vpat == "Supports" else "#ffb800" if vpat == "Partially Supports" else "#ff3366"))

            for c, it in enumerate([item_id, item_sc, item_lvl, item_st, item_title, item_vpat]):
                self.a11y_defects_table.setItem(r, c, it)

        if defects:
            self.a11y_defects_table.selectRow(0)
            self._display_a11y_defect_detail(defects[0])
        else:
            self.a11y_insp_title.setText("Zero accessibility criteria matched filter.")
            self.a11y_insp_meta.setText("")
            self.a11y_insp_desc.setText("")
            self.a11y_insp_impact.setText("")
            self.a11y_insp_code.clear()

    def _on_a11y_defect_selected(self):
        selected = self.a11y_defects_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        defects = getattr(self, "_filtered_a11y_defects", getattr(self, "_raw_a11y_defects", []))
        if 0 <= row < len(defects):
            self._display_a11y_defect_detail(defects[row])

    def _display_a11y_defect_detail(self, d: Dict[str, Any]):
        lvl = d.get("level", "AA")
        status = d.get("status", "PASSED")
        stat_col = "#00ff9d" if status == "PASSED" else "#ffb800" if status == "WARNING" else "#ff3366"

        self.a11y_insp_title.setText(f"{d.get('title')} [{d.get('defect_id')}]")
        self.a11y_insp_meta.setText(f"WCAG SC: {d.get('wcag_sc')} | Principle: {d.get('principle')} | Level {lvl} | Status: [{status}] | VPAT: {d.get('vpat_conformance')}")
        self.a11y_insp_meta.setStyleSheet(f"font-size: 12px; color: {stat_col}; font-weight: 700;")
        self.a11y_insp_desc.setText(f"Description: {d.get('description')}\nTarget: {d.get('target_element')}")
        self.a11y_insp_impact.setText(f"Assistive Tech Impact: {d.get('screen_reader_impact')}")
        self.a11y_insp_code.setPlainText(d.get("remediation_code", ""))

    def _filter_a11y_defects(self, fltr_type: str):
        raw = getattr(self, "_raw_a11y_defects", [])
        if fltr_type == "perceivable":
            self._filtered_a11y_defects = [d for d in raw if d.get("principle") == "Perceivable"]
        elif fltr_type == "operable":
            self._filtered_a11y_defects = [d for d in raw if d.get("principle") == "Operable"]
        elif fltr_type == "understandable":
            self._filtered_a11y_defects = [d for d in raw if d.get("principle") == "Understandable"]
        elif fltr_type == "robust":
            self._filtered_a11y_defects = [d for d in raw if d.get("principle") == "Robust"]
        elif fltr_type == "defects_only":
            self._filtered_a11y_defects = [d for d in raw if d.get("status") in ("DEFECT", "WARNING")]
        else:
            self._filtered_a11y_defects = list(raw)
        self._populate_a11y_defects_table()

    def _rerun_a11y_audit(self):
        target_str = self.target_path_edit.text().strip()
        if not target_str:
            QMessageBox.warning(self, "Missing Target", "Please enter a valid target URL or file path.")
            return

        target_type = self._selected_target_type
        if self.current_result and self.current_result.target:
            target = self.current_result.target
            findings = self.current_result.findings
        else:
            from ..core.models import ScanTarget
            target = ScanTarget(target_type=target_type, target_path=target_str, display_name=os.path.basename(target_str) or target_str)
            findings = []

        try:
            report = AccessibilityTester.run_tests(target, target.metadata, findings)
            target.metadata["accessibility_report"] = report.to_dict()
            if not self.current_result:
                from ..core.models import ScanResult, ScanMetrics
                self.current_result = ScanResult(
                    target=target,
                    level=ScanLevel.BASIC,
                    findings=findings,
                    metrics=ScanMetrics(total_checks=len(findings), passed=len(findings)),
                )
            self._populate_a11y(self.current_result)
            QMessageBox.information(
                self, "Accessibility Audit Complete",
                f"WCAG 2.2 accessibility audit finished for {target.display_name}!\n\n"
                f"WCAG Score: {report.metrics.wcag_score}%\n"
                f"Conformance: {report.metrics.conformance_status}\n"
                f"Criteria Checked: {report.metrics.total_criteria_checked}\n"
                f"A11y Defects Found: {report.metrics.defects_count}"
            )
        except Exception as e:
            QMessageBox.critical(self, "Audit Error", f"Failed to execute accessibility audit:\n{str(e)}")

    def _copy_vpat_markdown(self):
        md = self.a11y_deliverable_txt.toPlainText().strip()
        if not md:
            QMessageBox.warning(self, "No Deliverable", "No VPAT deliverable available to copy.")
            return
        QApplication.clipboard().setText(md)
        QMessageBox.information(self, "Report Copied", "Official VPAT 2.4 Accessibility Deliverable copied to clipboard!")

    def _copy_axe_script(self):
        script = self.a11y_axe_txt.toPlainText().strip()
        if not script:
            QMessageBox.warning(self, "No Script", "No Axe-core test script available to copy.")
            return
        QApplication.clipboard().setText(script)
        QMessageBox.information(self, "Script Copied", "Axe-Core & Playwright WCAG test suite copied to clipboard!")

    def _export_a11y_html(self):
        report = getattr(self, "_current_a11y_report", None)
        if not report and self.current_result and self.current_result.target:
            report = self.current_result.target.metadata.get("accessibility_report")
        if not report:
            QMessageBox.warning(self, "No Accessibility Report", "Please execute an audit first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save Accessibility Deliverable HTML", "WCAG_Accessibility_Deliverable.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_accessibility_report(report)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Professional WCAG & VPAT Deliverable HTML saved to:\n{file_path}")

    def _load_history(self):
        scans = self.db.get_all_scans()
        self.hist_table.setRowCount(0)
        for i, s in enumerate(scans):
            self.hist_table.insertRow(i)
            self.hist_table.setItem(i, 0, QTableWidgetItem(s["display_name"]))
            self.hist_table.setItem(i, 1, QTableWidgetItem(s["target_type"].upper()))
            self.hist_table.setItem(i, 2, QTableWidgetItem(s["level"].upper()))
            self.hist_table.setItem(i, 3, QTableWidgetItem(s["posture_grade"]))
            self.hist_table.setItem(i, 4, QTableWidgetItem(f"{s['security_score']}/100"))
            self.hist_table.setItem(i, 5, QTableWidgetItem(f"{s['critical_count']} / {s['high_count']}"))
            self.hist_table.setItem(i, 6, QTableWidgetItem(s["start_time"][:19].replace("T", " ")))
            self.hist_table.setItem(i, 7, QTableWidgetItem(f"{s['duration_seconds']}s"))
            self.hist_table.item(i, 0).setData(Qt.UserRole, s["scan_id"])

        if scans:
            self.rc_badge.setText(f"{len(scans)} scans recorded")

    def _load_selected_history(self):
        selected = self.hist_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "Select Scan", "Please select a scan row from the history table.")
            return
        row = selected[0].row()
        scan_id = self.hist_table.item(row, 0).data(Qt.UserRole)
        res = self.db.get_scan_by_id(scan_id)
        if res:
            self.current_result = res
            self._update_right_telemetry_with_result(res)
            self._populate_threat_model(res)
            self._populate_findings(res)
            self._populate_bugs(res)
            self._populate_web_history(res)
            self._populate_attacks(res)
            self._populate_automation(res)
            self._populate_api(res)
            self._populate_perf(res)
            self._populate_cicd(res)
            self._populate_db(res)
            self._populate_compat(res)
            self._populate_network(res)
            self._populate_logic(res)
            self._populate_memory(res)
            self._populate_a11y(res)
            self._switch_page(2)  # Threat Analysis

    def _delete_selected_history(self):
        selected = self.hist_table.selectionModel().selectedRows()
        if not selected:
            return
        row = selected[0].row()
        scan_id = self.hist_table.item(row, 0).data(Qt.UserRole)
        confirm = QMessageBox.question(
            self, "Confirm Delete", "Permanently delete this audit record from the database?",
            QMessageBox.Yes | QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            self.db.delete_scan(scan_id)
            self._load_history()

    def _export_html(self):
        if not self.current_result:
            QMessageBox.warning(self, "No Scan Result", "Please execute or load a security scan first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save HTML Audit Report", "CHARLO_Security_Report.html", "HTML Files (*.html)"
        )
        if file_path:
            html_content = HTMLReporter.generate_report(self.current_result)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            QMessageBox.information(self, "Report Exported", f"Security report successfully saved to:\n{file_path}")

    def _export_json(self):
        if not self.current_result:
            QMessageBox.warning(self, "No Scan Result", "Please execute or load a security scan first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON Audit Data", "CHARLO_Security_Data.json", "JSON Files (*.json)"
        )
        if file_path:
            json_content = JSONReporter.export(self.current_result)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(json_content)
            QMessageBox.information(self, "Data Exported", f"JSON audit data successfully saved to:\n{file_path}")

    def _export_sarif(self):
        """Exports compliant OASIS SARIF 2.1.0 JSON report for GitHub/GitLab Code Scanning."""
        if not self.current_result:
            QMessageBox.warning(self, "No Scan Result", "Please execute or load a security scan first.")
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self, "Save OASIS SARIF 2.1.0 Report", "CHARLO_Security_Report.sarif", "SARIF Files (*.sarif *.json)"
        )
        if file_path:
            sarif_content = SarifReporter.generate(self.current_result)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(sarif_content)
            QMessageBox.information(self, "SARIF Exported", f"OASIS SARIF 2.1.0 report saved to:\n{file_path}\nReady for GitHub Code Scanning / GitLab / Azure DevOps.")

    def _dispatch_webhook_alert(self):
        """Opens Webhook Alert Dispatcher dialog for Slack, Discord, and MS Teams."""
        if not self.current_result:
            QMessageBox.warning(self, "No Scan Result", "Please execute or load a security scan first.")
            return
        dlg = WebhookConfigDialog(self, result=self.current_result)
        dlg.exec()

    def _open_autopatch_workbench(self):
        """Opens Autonomous Auto-Patcher & Unified Git Diff Studio."""
        target_path = self.target_path_edit.text().strip()
        dlg = AutoPatchDialog(self, target_file=target_path if target_path.endswith((".py", ".js", ".ts", ".html")) else "vulnerable_component.py")
        dlg.exec()

    def _open_poc_sandbox(self):
        """Opens Live Interactive PoC Exploit Sandbox Runner."""
        url = self.target_path_edit.text().strip()
        dlg = PoCSandboxDialog(self, target_url=url if url.startswith(("http://", "https://")) else "https://")
        dlg.exec()

    def _show_patch_modal_for_finding(self):
        """Opens Auto-Patcher modal populated with selected finding telemetry."""
        if not self.current_result:
            QMessageBox.warning(self, "No Finding Selected", "Please run a scan and select a finding first.")
            return
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "Select Finding", "Please click on a finding in the table first.")
            return
        row = selected[0].row()
        cid = self.table.item(row, 0).text()
        match = next((f for f in self.current_result.findings if f.check_id == cid), None)
        if not match:
            return

        cat = (match.category or "SQL_INJECTION").upper()
        mapped_rule = "SQL_INJECTION" if "SQL" in cat else "XSS" if "XSS" in cat else "HARDCODED_SECRET" if "SECRET" in cat or "KEY" in cat else "MISSING_CSRF" if "CSRF" in cat else "UNSAFE_COOKIE" if "COOKIE" in cat else "A11Y_ARIA" if "ARIA" in cat or "A11Y" in cat else "SQL_INJECTION"
        sample = match.code_example or f"# Remediating: {match.title}\n# Affected Component: {match.affected_component}\n{match.remediation}\n"
        dlg = AutoPatchDialog(self, flaw_type=mapped_rule, flaw_id=match.check_id, sample_code=sample, target_file=match.affected_component or "vulnerable_code.py")
        dlg.exec()

    def _run_live_poc_for_finding(self):
        """Opens Live PoC Sandbox populated with target and selected finding probe."""
        if not self.current_result:
            QMessageBox.warning(self, "No Finding Selected", "Please run a scan and select a finding first.")
            return
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "Select Finding", "Please click on a finding in the table first.")
            return
        row = selected[0].row()
        cid = self.table.item(row, 0).text()
        match = next((f for f in self.current_result.findings if f.check_id == cid), None)
        if not match:
            return

        cat = (match.category or "").lower()
        probe_type = "sql_error" if "sql" in cat else "xss_probe" if "xss" in cat else "traversal" if "traversal" in cat or "file" in cat else "info_disclosure" if "header" in cat or "secret" in cat else "custom"
        target_url = self.current_result.target.raw_target if self.current_result.target else "https://"
        dlg = PoCSandboxDialog(self, target_url=target_url, flaw_id=match.check_id, probe_type=probe_type)
        dlg.exec()

    def _show_patch_modal_for_bug(self):
        """Opens Auto-Patcher modal populated with selected bug defect."""
        if not self.current_result:
            return
        selected = self.bugs_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "Select Defect", "Please select a defect from the bug finder table first.")
            return
        row = selected[0].row()
        cid = self.bugs_table.item(row, 0).text()
        match = next((f for f in self.current_result.findings if f.check_id == cid), None)
        sample = self.bug_insp_patch.toPlainText() or (match.code_example if match else "")
        comp = match.affected_component if match else "defect_component.py"
        dlg = AutoPatchDialog(self, flaw_type="SQL_INJECTION", flaw_id=cid, sample_code=sample, target_file=comp)
        dlg.exec()

    def _run_live_poc_for_bug(self):
        """Opens Live PoC Sandbox populated with bug verification probe."""
        target_url = self.current_result.target.raw_target if self.current_result and self.current_result.target else "https://"
        selected = self.bugs_table.selectionModel().selectedRows()
        cid = self.bugs_table.item(selected[0].row(), 0).text() if selected else "BUG-PROBE"
        dlg = PoCSandboxDialog(self, target_url=target_url, flaw_id=cid, probe_type="custom")
        dlg.exec()

    def _run_live_poc_for_api(self):
        """Opens Live PoC Sandbox prefilled with selected REST endpoint."""
        selected = self.api_table.selectionModel().selectedRows()
        if not selected:
            QMessageBox.information(self, "Select Endpoint", "Please select an API endpoint from the table first.")
            return
        row = selected[0].row()
        method = self.api_table.item(row, 1).text()
        endpoint = self.api_table.item(row, 2).text()
        dlg = PoCSandboxDialog(self, target_url=endpoint, default_method=method, flaw_id=f"API-{row+1}")
        dlg.exec()

    def _show_patch_modal_for_api(self):
        """Opens Auto-Patcher modal prefilled with API developer fix."""
        selected = self.api_table.selectionModel().selectedRows()
        patch_text = self.api_insp_patch.toPlainText()
        dlg = AutoPatchDialog(self, flaw_type="SQL_INJECTION", sample_code=patch_text, target_file="api_handler.py")
        dlg.exec()

    def _run_live_poc_for_logic(self):
        """Opens Live PoC Sandbox prefilled with business logic sequence probe."""
        target_url = self.current_result.target.raw_target if self.current_result and self.current_result.target else "https://"
        poc_text = self.logic_insp_poc.toPlainText()
        dlg = PoCSandboxDialog(self, target_url=target_url, flaw_id="BIZ-LOGIC-POC", probe_type="custom")
        if poc_text:
            dlg.payload_edit.setText(poc_text)
            dlg.method_combo.setCurrentText("POST")
        dlg.exec()

    def _show_patch_modal_for_logic(self):
        """Opens Auto-Patcher modal prefilled with logic remediation pattern."""
        remed_text = self.logic_insp_remed.toPlainText()
        dlg = AutoPatchDialog(self, flaw_type="SQL_INJECTION", sample_code=remed_text, target_file="business_service.py")
        dlg.exec()
