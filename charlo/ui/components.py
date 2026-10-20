"""
Custom UI Components for CHARLO Testing Agent matching the Cyberpunk Obsidian & Crimson design.
"""

import math
from PySide6.QtCore import Qt, QRect, QRectF, QPoint, QPointF, Signal, Property, QTimer
from PySide6.QtGui import (
    QPainter, QColor, QPen, QBrush, QRadialGradient, QLinearGradient,
    QPainterPath, QFont, QIcon, QPolygonF
)
from PySide6.QtWidgets import (
    QWidget, QFrame, QVBoxLayout, QHBoxLayout, QLabel, QPushButton
)


class OrbLogoWidget(QWidget):
    """
    Sleek circular 3D dark orb lens logo on top left of header.
    """
    def __init__(self, size: int = 42, parent=None):
        super().__init__(parent)
        self.setFixedSize(size, size)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        cx, cy = w / 2.0, h / 2.0
        r = (min(w, h) / 2.0) - 2.0

        # Outer dark ring
        painter.setPen(QPen(QColor("#252b3b"), 1.5))
        painter.setBrush(QColor("#0d1017"))
        painter.drawEllipse(QPointF(cx, cy), r, r)

        # Concentric groove
        painter.setPen(QPen(QColor("#181d29"), 1.0))
        painter.drawEllipse(QPointF(cx, cy), r * 0.75, r * 0.75)

        # Inner 3D spherical radial gradient
        grad = QRadialGradient(cx - r * 0.25, cy - r * 0.25, r * 0.6)
        grad.setColorAt(0.0, QColor("#3a4358"))
        grad.setColorAt(0.4, QColor("#161a24"))
        grad.setColorAt(1.0, QColor("#090b10"))

        painter.setPen(Qt.NoPen)
        painter.setBrush(grad)
        painter.drawEllipse(QPointF(cx, cy), r * 0.6, r * 0.6)

        # Subtle crimson core reflection
        c_grad = QRadialGradient(cx + r * 0.1, cy + r * 0.1, r * 0.25)
        c_grad.setColorAt(0.0, QColor(255, 42, 68, 120))
        c_grad.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setBrush(c_grad)
        painter.drawEllipse(QPointF(cx, cy), r * 0.25, r * 0.25)


class SecurityPulseWidget(QWidget):
    """
    Circular radar / security pulse widget with concentric circles,
    subtle glowing grid, and central crimson security shield.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(140, 95)
        self._angle = 0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._rotate)
        self._timer.start(50)  # 20 FPS gentle sweep

    def _rotate(self):
        self._angle = (self._angle + 2) % 360
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        cx, cy = w / 2.0, h / 2.0
        max_r = min(w, h) / 2.0 - 6.0

        # Draw concentric radar rings
        for i, frac in enumerate([0.3, 0.55, 0.8, 1.0]):
            r = max_r * frac
            pen_color = QColor(255, 42, 68, int(25 + i * 15)) if i == 3 else QColor(40, 48, 68, 90)
            pen = QPen(pen_color, 1.0, Qt.DotLine if i % 2 == 1 else Qt.SolidLine)
            painter.setPen(pen)
            painter.setBrush(Qt.NoBrush)
            painter.drawEllipse(QPointF(cx, cy), r, r)

        # Radar sweep sector
        sweep_grad = QRadialGradient(cx, cy, max_r)
        sweep_grad.setColorAt(0.0, QColor(255, 42, 68, 60))
        sweep_grad.setColorAt(0.7, QColor(255, 42, 68, 20))
        sweep_grad.setColorAt(1.0, QColor(0, 0, 0, 0))

        painter.save()
        painter.translate(cx, cy)
        painter.rotate(self._angle)
        painter.setPen(Qt.NoPen)
        painter.setBrush(sweep_grad)
        path = QPainterPath()
        path.moveTo(0, 0)
        path.arcTo(-max_r, -max_r, max_r * 2, max_r * 2, 0, 45)
        path.closeSubpath()
        painter.drawPath(path)
        painter.restore()

        # Crosshairs
        painter.setPen(QPen(QColor(60, 70, 95, 60), 1.0, Qt.DashLine))
        painter.drawLine(QPointF(cx - max_r, cy), QPointF(cx + max_r, cy))
        painter.drawLine(QPointF(cx, cy - max_r), QPointF(cx, cy + max_r))

        # Central glowing crimson shield
        shield_r = 13.0
        # Glow
        glow = QRadialGradient(cx, cy, shield_r * 1.8)
        glow.setColorAt(0.0, QColor(255, 42, 68, 180))
        glow.setColorAt(0.6, QColor(255, 42, 68, 60))
        glow.setColorAt(1.0, QColor(0, 0, 0, 0))
        painter.setPen(Qt.NoPen)
        painter.setBrush(glow)
        painter.drawEllipse(QPointF(cx, cy), shield_r * 1.8, shield_r * 1.8)

        # Shield outline
        shield_path = QPainterPath()
        shield_path.moveTo(cx, cy - shield_r * 0.9)
        shield_path.lineTo(cx + shield_r * 0.75, cy - shield_r * 0.5)
        shield_path.lineTo(cx + shield_r * 0.6, cy + shield_r * 0.4)
        shield_path.lineTo(cx, cy + shield_r * 0.9)
        shield_path.lineTo(cx - shield_r * 0.6, cy + shield_r * 0.4)
        shield_path.lineTo(cx - shield_r * 0.75, cy - shield_r * 0.5)
        shield_path.closeSubpath()

        painter.setPen(QPen(QColor("#ffffff"), 1.5))
        painter.setBrush(QColor("#ff2a44"))
        painter.drawPath(shield_path)


class ToggleSwitch(QWidget):
    """
    Modern iOS / Cyberpunk style animated red pill toggle switch.
    """
    toggled = Signal(bool)

    def __init__(self, checked: bool = True, parent=None):
        super().__init__(parent)
        self.setFixedSize(48, 26)
        self._checked = checked
        self.setCursor(Qt.PointingHandCursor)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, checked: bool):
        if self._checked != checked:
            self._checked = checked
            self.toggled.emit(self._checked)
            self.update()

    def mousePressEvent(self, event):
        self._checked = not self._checked
        self.toggled.emit(self._checked)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        r = h / 2.0

        # Background track
        track_color = QColor("#ff2a44") if self._checked else QColor("#222736")
        painter.setPen(Qt.NoPen)
        painter.setBrush(track_color)
        painter.drawRoundedRect(0, 0, w, h, r, r)

        # Thumb
        thumb_r = r - 3.0
        thumb_x = (w - r) if self._checked else r
        painter.setBrush(QColor("#ffffff"))
        painter.drawEllipse(QPointF(thumb_x, r), thumb_r, thumb_r)


class TargetTypeCard(QFrame):
    """
    Interactive Target Selection Card with glowing red border, circular icon,
    title, subtitle, description, and circular arrow button.
    Compact and responsive to eliminate text overflow.
    """
    clicked = Signal()

    def __init__(
        self,
        icon_text: str,
        title: str,
        subtitle: str,
        description: str,
        is_selected: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._is_selected = is_selected
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(86)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(10)

        # Left circular icon container
        self.icon_box = QFrame()
        self.icon_box.setFixedSize(40, 40)
        ib_layout = QVBoxLayout(self.icon_box)
        ib_layout.setContentsMargins(0, 0, 0, 0)
        ib_layout.setAlignment(Qt.AlignCenter)

        self.icon_label = QLabel(icon_text)
        self.icon_label.setAlignment(Qt.AlignCenter)
        self.icon_label.setStyleSheet("font-size: 18px;")
        ib_layout.addWidget(self.icon_label)
        layout.addWidget(self.icon_box)

        # Middle text VBox
        vbox = QVBoxLayout()
        vbox.setSpacing(1)
        vbox.setAlignment(Qt.AlignVCenter)

        title_row = QHBoxLayout()
        title_row.setSpacing(5)
        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #ffffff;")
        self.sub_lbl = QLabel(subtitle)
        self.sub_lbl.setStyleSheet("font-size: 10.5px; font-weight: 700; color: #ff2a44;")
        title_row.addWidget(self.title_lbl)
        title_row.addWidget(self.sub_lbl)
        title_row.addStretch()
        vbox.addLayout(title_row)

        self.desc_lbl = QLabel(description)
        self.desc_lbl.setStyleSheet("font-size: 10.5px; color: #7b8497; line-height: 1.2;")
        self.desc_lbl.setWordWrap(True)
        vbox.addWidget(self.desc_lbl)
        layout.addLayout(vbox, stretch=1)

        # Right circular arrow button
        self.arrow_btn = QFrame()
        self.arrow_btn.setFixedSize(26, 26)
        ab_layout = QVBoxLayout(self.arrow_btn)
        ab_layout.setContentsMargins(0, 0, 0, 0)
        ab_layout.setAlignment(Qt.AlignCenter)
        self.arrow_lbl = QLabel("➔")
        self.arrow_lbl.setAlignment(Qt.AlignCenter)
        self.arrow_lbl.setStyleSheet("font-size: 11px; color: #8b93a4;")
        ab_layout.addWidget(self.arrow_lbl)
        layout.addWidget(self.arrow_btn)

        self._update_style()

    def setSelected(self, selected: bool):
        self._is_selected = selected
        self._update_style()

    def isSelected(self) -> bool:
        return self._is_selected

    def _update_style(self):
        if self._is_selected:
            self.setStyleSheet("""
                TargetTypeCard {
                    background-color: #1a1116;
                    border: 1.5px solid #ff2a44;
                    border-radius: 10px;
                }
            """)
            self.icon_box.setStyleSheet("""
                QFrame {
                    background-color: #3b141b;
                    border: 1px solid #ff2a44;
                    border-radius: 20px;
                }
            """)
            self.arrow_btn.setStyleSheet("""
                QFrame {
                    background-color: #ff2a44;
                    border-radius: 13px;
                }
            """)
            self.arrow_lbl.setStyleSheet("font-size: 11px; color: #ffffff;")
        else:
            self.setStyleSheet("""
                TargetTypeCard {
                    background-color: #12151d;
                    border: 1px solid #1e2330;
                    border-radius: 10px;
                }
                TargetTypeCard:hover {
                    border: 1px solid #3d465e;
                    background-color: #161a24;
                }
            """)
            self.icon_box.setStyleSheet("""
                QFrame {
                    background-color: #1e171b;
                    border: 1px solid #331f24;
                    border-radius: 20px;
                }
            """)
            self.arrow_btn.setStyleSheet("""
                QFrame {
                    background-color: #1c212c;
                    border-radius: 13px;
                }
            """)
            self.arrow_lbl.setStyleSheet("font-size: 11px; color: #8b93a4;")

    def mousePressEvent(self, event):
        self.clicked.emit()


class SidebarItemWidget(QFrame):
    """
    Left sidebar navigation button with icon, bold title, and muted subtitle.
    Active state displays crimson left border + glowing subtle red gradient.
    """
    clicked = Signal()

    def __init__(self, icon_str: str, title: str, subtitle: str, is_active: bool = False, parent=None):
        super().__init__(parent)
        self._is_active = is_active
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(38)
        self.setMaximumHeight(44)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 3, 8, 3)
        layout.setSpacing(8)

        self.icon_lbl = QLabel(icon_str)
        self.icon_lbl.setFixedWidth(20)
        self.icon_lbl.setAlignment(Qt.AlignCenter)
        self.icon_lbl.setStyleSheet("font-size: 14px;")
        layout.addWidget(self.icon_lbl)

        vbox = QVBoxLayout()
        vbox.setSpacing(1)
        vbox.setAlignment(Qt.AlignVCenter)

        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("font-size: 12px; font-weight: 700; color: #ffffff;")
        self.sub_lbl = QLabel(subtitle)
        self.sub_lbl.setStyleSheet("font-size: 9.5px; color: #7b8497;")

        vbox.addWidget(self.title_lbl)
        vbox.addWidget(self.sub_lbl)
        layout.addLayout(vbox, stretch=1)

        self._update_style()

    def setActive(self, active: bool):
        self._is_active = active
        self._update_style()

    def _update_style(self):
        if self._is_active:
            self.setStyleSheet("""
                SidebarItemWidget {
                    background-color: #231217;
                    border: 1px solid #ff2a44;
                    border-radius: 8px;
                }
            """)
            self.title_lbl.setStyleSheet("font-size: 12px; font-weight: 800; color: #ff334b;")
            self.sub_lbl.setStyleSheet("font-size: 9.5px; color: #cf7985;")
        else:
            self.setStyleSheet("""
                SidebarItemWidget {
                    background-color: transparent;
                    border: 1px solid transparent;
                    border-radius: 8px;
                }
                SidebarItemWidget:hover {
                    background-color: #161922;
                    border: 1px solid #232838;
                }
            """)
            self.title_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #d0d7e6;")
            self.sub_lbl.setStyleSheet("font-size: 9.5px; color: #7b8497;")

    def mousePressEvent(self, event):
        self.clicked.emit()
