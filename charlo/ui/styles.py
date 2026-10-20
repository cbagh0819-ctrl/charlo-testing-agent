"""
Cyber Crimson & Obsidian Workstation Theme for CHARLO Testing Agent.
Ultra-sleek dark mode AI security laboratory aesthetic matching the reference mockup.
"""

WORKSTATION_STYLE = """
/* Global Window & Base Palette */
QMainWindow, QWidget {
    background-color: #090b0f;
    color: #e4e9f2;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 13px;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #0d1016;
    width: 8px;
    margin: 0px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #232938;
    min-height: 25px;
    border-radius: 4px;
}
QScrollBar::handle:vertical:hover {
    background: #ff2a44;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: #0d1016;
    height: 8px;
    margin: 0px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal {
    background: #232938;
    min-width: 25px;
    border-radius: 4px;
}
QScrollBar::handle:horizontal:hover {
    background: #ff2a44;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}

/* Header Bar */
#HeaderBar {
    background-color: #0b0d12;
    border-bottom: 1px solid #191e2a;
    padding: 10px 24px;
}

#AppTitle {
    font-size: 16px;
    font-weight: 900;
    color: #ff2a44;
    letter-spacing: 0.8px;
}

#AppSubtitle {
    font-size: 9.5px;
    color: #7b8497;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}

/* Floating Pill Nav Bar */
#TopNavPillBar {
    background-color: #12151d;
    border: 1px solid #1f2533;
    border-radius: 18px;
    padding: 2px 4px;
}

.PillNavBtn {
    background-color: transparent;
    color: #8b93a4;
    border: none;
    border-radius: 13px;
    padding: 4px 10px;
    font-size: 11.5px;
    font-weight: 700;
}
.PillNavBtn:hover {
    color: #ffffff;
    background-color: #1a1e2a;
}
.PillNavBtn:checked, .PillNavBtn[active="true"] {
    background-color: #ff2a44;
    color: #ffffff;
    font-weight: 800;
}

/* Cards & Panel Frames */
.QFrame, #CardFrame, #PanelBox {
    background-color: #11141c;
    border: 1px solid #1a202c;
    border-radius: 12px;
}

/* Buttons */
QPushButton {
    background-color: #161a24;
    color: #e4e9f2;
    border: 1px solid #242c3d;
    border-radius: 8px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 12.5px;
}
QPushButton:hover {
    background-color: #1f2433;
    border-color: #3b455c;
    color: #ffffff;
}
QPushButton:pressed {
    background-color: #141720;
}

/* Primary Vibrant Red Action Buttons */
#PrimaryRedBtn {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff2a44, stop:1 #e61933);
    color: #ffffff;
    border: none;
    font-weight: 800;
    font-size: 14.5px;
    padding: 12px 28px;
    border-radius: 10px;
    letter-spacing: 0.5px;
}
#PrimaryRedBtn:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff475e, stop:1 #ff2a44);
}
#PrimaryRedBtn:pressed {
    background: #cc152b;
}

#SecondaryDarkBtn {
    background-color: #141822;
    color: #ffffff;
    border: 1px solid #ff2a44;
    font-weight: 700;
    border-radius: 10px;
    padding: 10px 20px;
    font-size: 13px;
}
#SecondaryDarkBtn:hover {
    background-color: #241419;
    border-color: #ff475e;
}

/* Form Inputs & Controls */
QLineEdit, QComboBox, QTextEdit {
    background-color: #0e1118;
    border: 1px solid #1c2230;
    border-radius: 8px;
    padding: 9px 14px;
    color: #e4e9f2;
    font-size: 13px;
    selection-background-color: #ff2a44;
    selection-color: #ffffff;
}
QLineEdit:focus, QComboBox:focus, QTextEdit:focus {
    border: 1px solid #ff2a44;
    background-color: #10141d;
}

QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 25px;
    border-left: 1px solid #1c2230;
}

QComboBox QAbstractItemView {
    background-color: #0e1118;
    border: 1px solid #252c3e;
    selection-background-color: #26141a;
    selection-color: #ff2a44;
    color: #e4e9f2;
    outline: 0px;
}

/* Table Widget */
QTableWidget {
    background-color: #11141c;
    border: 1px solid #1a202c;
    gridline-color: #171c26;
    border-radius: 10px;
    color: #e4e9f2;
    selection-background-color: #221318;
    selection-color: #ff475e;
}
QTableWidget::item {
    padding: 7px 10px;
    border-bottom: 1px solid #151a24;
}
QHeaderView::section {
    background-color: #0d1016;
    color: #7b8497;
    padding: 9px 12px;
    font-weight: 800;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border: none;
    border-bottom: 1px solid #1c2230;
}

/* Progress Bar */
QProgressBar {
    background-color: #0e1118;
    border: 1px solid #1c2230;
    border-radius: 6px;
    text-align: center;
    color: #ffffff;
    font-weight: 800;
    font-size: 12px;
    height: 20px;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff2a44, stop:1 #ff6b22);
    border-radius: 5px;
}

/* Log Terminal Box */
#LogConsole {
    background-color: #07090d;
    border: 1px solid #191f2c;
    font-family: "Cascadia Code", Consolas, Monaco, "Courier New", monospace;
    font-size: 12px;
    color: #a4b8d4;
    border-radius: 8px;
    padding: 12px;
    line-height: 1.4;
}

/* Feature Badge Pills */
.FeatureBadgePill {
    background-color: #121620;
    border: 1px solid #1f2636;
    border-radius: 14px;
    padding: 4px 12px;
    color: #cbd5e1;
    font-size: 11.5px;
    font-weight: 600;
}
"""
