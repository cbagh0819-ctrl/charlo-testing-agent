"""
Unit tests for CHARLO Testing Agent UI components and MainWindow layout.
"""

import os
import pytest

# Ensure offscreen Qt platform for headless CI / testing
os.environ["QT_QPA_PLATFORM"] = "offscreen"

from PySide6.QtWidgets import QApplication, QLabel
from charlo.core.models import TargetType
from charlo.ui.components import (
    OrbLogoWidget, SecurityPulseWidget, ToggleSwitch, TargetTypeCard, SidebarItemWidget
)
from charlo.ui.main_window import MainWindow


@pytest.fixture(scope="session")
def qapp():
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_custom_ui_components(qapp):
    """Verify that all custom visual components instantiate and respond to signals cleanly."""
    orb = OrbLogoWidget(size=44)
    assert orb.width() == 44
    assert orb.height() == 44

    radar = SecurityPulseWidget()
    assert radar.minimumWidth() >= 120

    toggle = ToggleSwitch(checked=True)
    assert toggle.isChecked() is True
    toggle.setChecked(False)
    assert toggle.isChecked() is False

    card = TargetTypeCard("🤖", "Android", "(.apk)", "Test APK", is_selected=False)
    assert card.isSelected() is False
    card.setSelected(True)
    assert card.isSelected() is True

    sidebar_item = SidebarItemWidget("🏠", "New Scan", "Subtitle", is_active=True)
    assert sidebar_item._is_active is True
    sidebar_item.setActive(False)
    assert sidebar_item._is_active is False
    # Verify no duplicate widgets inside sidebar item
    labels = sidebar_item.findChildren(QLabel)
    assert len(labels) == 3  # 1 icon, 1 title, 1 subtitle


def test_main_window_full_initialization(qapp):
    """Verify MainWindow builds 3-column layout, all 18 pages, and navigates seamlessly."""
    win = MainWindow()
    assert win.pages.count() == 18
    assert len(win._sidebar_items) == 18
    assert len(win._top_pill_btns) == 18

    # Test page switching
    win._switch_page(2)
    assert win.pages.currentIndex() == 2
    assert win._sidebar_items[2]._is_active is True

    win._switch_page(6)  # Test a Hack page
    assert win.pages.currentIndex() == 6
    assert win._sidebar_items[6]._is_active is True

    win._switch_page(8)  # QA Automation page
    assert win.pages.currentIndex() == 8
    assert win._sidebar_items[8]._is_active is True
    assert win.qa_tabs.count() == 4
    assert win.qa_table.columnCount() == 5

    win._switch_page(9)  # API Testing page
    assert win.pages.currentIndex() == 9
    assert win._sidebar_items[9]._is_active is True
    assert win.api_tabs.count() == 4
    assert win.api_table.columnCount() == 6

    win._switch_page(10)  # Concurrency / Load Testing page
    assert win.pages.currentIndex() == 10
    assert win._sidebar_items[10]._is_active is True
    assert win.perf_tabs.count() == 4
    assert win.perf_percentiles_table.columnCount() == 4
    assert win.perf_codes_table.columnCount() == 3

    win._switch_page(11)  # CI/CD Quality Gate page
    assert win.pages.currentIndex() == 11
    assert win._sidebar_items[11]._is_active is True
    assert win.cicd_tabs.count() == 5

    win._switch_page(12)  # Database QA page
    assert win.pages.currentIndex() == 12
    assert win._sidebar_items[12]._is_active is True
    assert win.db_tabs.count() == 3
    assert win.db_tables_table.columnCount() == 5

    win._switch_page(13)  # Viewport & A11y page
    assert win.pages.currentIndex() == 13
    assert win._sidebar_items[13]._is_active is True
    assert win.compat_tabs.count() == 4
    assert win.compat_devices_table.columnCount() == 7
    assert win.compat_defects_table.columnCount() == 6

    win._switch_page(14)  # Network & TLS page
    assert win.pages.currentIndex() == 14
    assert win._sidebar_items[14]._is_active is True
    assert win.net_tabs.count() == 3
    assert win.net_telemetry_table.columnCount() == 2
    assert win.net_defects_table.columnCount() == 6

    win._switch_page(15)  # Business Logic QA page
    assert win.pages.currentIndex() == 15
    assert win._sidebar_items[15]._is_active is True
    assert win.logic_tabs.count() == 3
    assert win.logic_workflows_table.columnCount() == 1
    assert win.logic_defects_table.columnCount() == 6

    win._switch_page(16)  # Memory & Resource QA page
    assert win.pages.currentIndex() == 16
    assert win._sidebar_items[16]._is_active is True
    assert win.mem_tabs.count() == 3
    assert win.mem_telemetry_table.columnCount() == 2
    assert win.mem_defects_table.columnCount() == 6

    win._switch_page(17)  # Accessibility QA page
    assert win.pages.currentIndex() == 17
    assert win._sidebar_items[17]._is_active is True
    assert win.a11y_tabs.count() == 3
    assert win.a11y_landmarks_table.columnCount() == 4
    assert win.a11y_defects_table.columnCount() == 6

    # Test target type selection
    win._select_target_type(TargetType.APK)
    assert win._selected_target_type == TargetType.APK
    assert win.card_apk.isSelected() is True
    assert win.card_web.isSelected() is False

    win._select_target_type(TargetType.EXE)
    assert win._selected_target_type == TargetType.EXE

    win._select_target_type(TargetType.WEB)
    assert win._selected_target_type == TargetType.WEB
    assert win.card_web.isSelected() is True

    # Test right telemetry chips & action buttons
    assert win.metric_threats_lbl.text() == "0 Threats"
    assert win.metric_vulns_lbl.text() == "0 Vulns"
    assert win.metric_suspicious_lbl.text() == "0 Defects"
    assert win.metric_score_lbl.text() == "-- Score"

    assert win.start_btn.isHidden() is False
    assert win.start_bug_btn.isHidden() is False
    assert win.start_atk_btn.isHidden() is True
    assert win.start_a11y_btn.isHidden() is False
    assert "Accessibility" in win.start_a11y_btn.text()

    # Test Homepage Shortcuts & Quick Launchers
    assert win.btn_hp_open_a11y.isHidden() is False
    assert win.btn_hp_open_logic.isHidden() is False
    assert win.btn_hp_open_compat.isHidden() is False
    assert win.btn_hp_open_qa.isHidden() is False

    # Test 1-click navigation from homepage shortcut buttons
    win._switch_page(0)
    assert win.pages.currentIndex() == 0
    win.btn_hp_open_a11y.click()
    assert win.pages.currentIndex() == 17

    win.btn_hp_open_logic.click()
    assert win.pages.currentIndex() == 15

    win.btn_hp_open_compat.click()
    assert win.pages.currentIndex() == 13

    win.btn_hp_open_qa.click()
    assert win.pages.currentIndex() == 8

    # Test global shortcut triggering
    win._switch_page(0)
    assert win.pages.currentIndex() == 0
    win._sc_a11y.activated.emit()
    assert win.pages.currentIndex() == 17

    win._sc_home.activated.emit()
    assert win.pages.currentIndex() == 0

    # Test metric card labels
    assert win.card_grade.findChildren(object)[-1].text() == "GRADE"
    assert win.card_bug_total.findChildren(object)[-1].text() == "TOTAL"
    assert win.card_hist_age.findChildren(object)[-1].text() == "AGE"
    assert win.card_atk_survival.findChildren(object)[-1].text() == "SURVIVAL"

    # Test top pill buttons have proper minimumWidth so text is never clipped
    for btn in win._top_pill_btns:
        text_w = btn.fontMetrics().horizontalAdvance(btn.text())
        assert btn.minimumWidth() >= text_w + 14

    win.close()
