#pragma once
#include <QString>
#include <QColor>
#include <QFont>

namespace Style {

namespace Color {
    inline const QColor BgDeep      = QColor("#060b10");
    inline const QColor BgBase      = QColor("#0d1117");
    inline const QColor BgSurface   = QColor("#131920");
    inline const QColor BgCard      = QColor("#1a2130");
    inline const QColor BgHover     = QColor("#1e2840");
    inline const QColor BgSelected  = QColor("#163050");
    inline const QColor BorderDim   = QColor("#1c2530");
    inline const QColor Border      = QColor("#253040");
    inline const QColor BorderLight = QColor("#3a4f65");
    inline const QColor TextPrimary = QColor("#dde8f5");
    inline const QColor TextSecond  = QColor("#6e8399");
    inline const QColor TextMuted   = QColor("#334455");
    inline const QColor TextLink    = QColor("#5aabff");
    inline const QColor AccentBlue  = QColor("#1d6ef5");
    inline const QColor Success     = QColor("#20d060");
    inline const QColor SuccessBg   = QColor("#081f12");
    inline const QColor Warning     = QColor("#f0b800");
    inline const QColor WarningBg   = QColor("#1a1500");
    inline const QColor Danger      = QColor("#f04040");
    inline const QColor DangerBg    = QColor("#1f0808");

    inline QColor forState(const QString &s) {
        if (s == "ESTABLISHED") return Success;
        if (s == "UDP_ACTIVE")  return QColor("#30c0f0");
        if (s == "SYN_SENT")    return Warning;
        if (s == "SYN_RECV")    return Warning;
        if (s == "FIN_WAIT")    return TextSecond;
        return TextMuted;
    }
    inline QColor forRtt(double ms) {
        if (ms <= 0)  return TextMuted;
        if (ms < 50)  return Success;
        if (ms < 150) return Warning;
        return Danger;
    }
}

namespace Font {
    inline QFont mono(int px = 14) {
        QFont f("Ubuntu Mono");
        f.setPixelSize(px);
        return f;
    }
    inline QFont heading(int px = 16) {
        QFont f("Ubuntu Mono");
        f.setPixelSize(px);
        f.setWeight(QFont::Medium);
        return f;
    }
}

inline QString globalStyleSheet() {
    return R"(

/* ── Reset ───────────────────────────────────────────────────── */
* { font-family: "Ubuntu Mono"; outline: none; }

/* ── Base ────────────────────────────────────────────────────── */
QMainWindow {
    background-color: #060b10;
}
QWidget {
    background-color: #0d1117;
    color: #dde8f5;
    font-family: "Ubuntu Mono";
    font-size: 14px;
}

/* ── Sidebar ─────────────────────────────────────────────────── */
#Sidebar {
    background-color: #0a0f16;
    border-right: 1px solid #1c2530;
}
#SidebarLogo {
    background-color: #0a0f16;
    border-bottom: 1px solid #1c2530;
}
#SectionTitle {
    color: #334455;
    font-size: 10px;
    font-weight: 700;
    padding: 12px 16px 5px;
    letter-spacing: 2px;
}

/* ── Nav buttons ─────────────────────────────────────────────── */
QPushButton#NavButton {
    background: transparent;
    border: none;
    border-radius: 0;
    color: #6e8399;
    text-align: left;
    padding: 11px 18px;
    font-size: 14px;
    font-weight: 400;
}
QPushButton#NavButton:hover {
    background-color: #131920;
    color: #dde8f5;
}
QPushButton#NavButton[active="true"] {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #163050, stop:1 #0d1117);
    color: #5aabff;
    border-left: 3px solid #1d6ef5;
    padding-left: 15px;
    font-weight: 600;
}

/* ── Top bar ─────────────────────────────────────────────────── */
#TopBar {
    background-color: #0a0f16;
    border-bottom: 1px solid #1c2530;
    padding: 0 20px;
    min-height: 58px;
    max-height: 58px;
}

/* ── Tables ──────────────────────────────────────────────────── */
QTableView, QTableWidget {
    background-color: #0d1117;
    alternate-background-color: #0f1520;
    border: none;
    gridline-color: #131a24;
    selection-background-color: #163050;
    selection-color: #dde8f5;
    font-size: 14px;
    font-family: "Ubuntu Mono";
}
QTableView::item, QTableWidget::item {
    padding: 7px 14px;
    border-bottom: 1px solid #131a24;
}
QTableView::item:selected, QTableWidget::item:selected {
    background-color: #163050;
}
QTableView::item:hover, QTableWidget::item:hover {
    background-color: #131920;
}
QHeaderView { background-color: #0a0f16; border: none; }
QHeaderView::section {
    background-color: #0a0f16;
    color: #334455;
    font-size: 11px;
    font-weight: 700;
    padding: 9px 14px;
    border: none;
    border-bottom: 1px solid #1c2530;
    letter-spacing: 1.5px;
}
QHeaderView::section:hover {
    background-color: #131920;
    color: #6e8399;
}

/* ── Scrollbars ──────────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent; width: 5px; border: none;
}
QScrollBar::handle:vertical {
    background: #253040; border-radius: 2px; min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #3a4f65; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical
{ height:0; background:transparent; border:none; }

QScrollBar:horizontal {
    background: transparent; height: 5px; border: none;
}
QScrollBar::handle:horizontal {
    background: #253040; border-radius: 2px; min-width: 30px;
}
QScrollBar::handle:horizontal:hover { background: #3a4f65; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal
{ width:0; background:transparent; border:none; }

/* ── Inputs ──────────────────────────────────────────────────── */
QLineEdit {
    background-color: #131920;
    border: 1px solid #253040;
    border-radius: 8px;
    color: #dde8f5;
    padding: 8px 14px;
    font-size: 14px;
    selection-background-color: #163050;
}
QLineEdit:focus {
    border-color: #1d6ef5;
    background-color: #0f1828;
}
QLineEdit:hover { border-color: #3a4f65; }

/* ── ComboBox ────────────────────────────────────────────────── */
QComboBox {
    background-color: #131920;
    border: 1px solid #253040;
    border-radius: 8px;
    color: #dde8f5;
    padding: 8px 14px;
    font-size: 14px;
    min-width: 130px;
}
QComboBox:hover { border-color: #3a4f65; }
QComboBox:focus { border-color: #1d6ef5; }
QComboBox::drop-down { border:none; width:24px; }
QComboBox QAbstractItemView {
    background-color: #131920;
    border: 1px solid #253040;
    border-radius: 8px;
    color: #dde8f5;
    selection-background-color: #163050;
    selection-color: #5aabff;
    padding: 4px;
    font-size: 14px;
}
QComboBox QAbstractItemView::item {
    padding: 8px 14px;
    border-radius: 4px;
    min-height: 28px;
}

/* ── Splitter ────────────────────────────────────────────────── */
QSplitter::handle { background-color: #1c2530; }
QSplitter::handle:hover { background-color: #253040; }

/* ── Status bar ──────────────────────────────────────────────── */
QStatusBar {
    background-color: #0a0f16;
    border-top: 1px solid #1c2530;
    color: #334455;
    font-size: 12px;
    padding: 0 16px;
    min-height: 28px;
}
QStatusBar QLabel {
    color: #334455;
    font-size: 12px;
    padding: 0 6px;
}

/* ── Detail panel ────────────────────────────────────────────── */
#DetailPanel {
    background-color: #0a0f16;
    border-top: 1px solid #1c2530;
}

/* ── Stat cards ──────────────────────────────────────────────── */
#StatCard {
    background-color: #131920;
    border: 1px solid #1c2530;
    border-radius: 12px;
}
#StatCard:hover {
    background-color: #1a2130;
    border-color: #253040;
}

/* ── List widget ─────────────────────────────────────────────── */
QListWidget {
    background-color: #0d1117;
    border: none;
    font-size: 14px;
    outline: none;
}
QListWidget::item {
    padding: 11px 16px;
    border-bottom: 1px solid #131a24;
}
QListWidget::item:selected {
    background-color: #163050;
    color: #5aabff;
    border-left: 3px solid #1d6ef5;
    padding-left: 13px;
}
QListWidget::item:hover { background-color: #131920; }

/* ── Push buttons ────────────────────────────────────────────── */
QPushButton {
    background-color: #131920;
    border: 1px solid #253040;
    border-radius: 8px;
    color: #dde8f5;
    padding: 8px 18px;
    font-size: 14px;
}
QPushButton:hover {
    background-color: #1a2130;
    border-color: #3a4f65;
}
QPushButton:pressed { background-color: #163050; }

/* ── Tab bar ─────────────────────────────────────────────────── */
QTabWidget::pane { border: none; background-color: #0d1117; }
QTabBar::tab {
    background: transparent;
    color: #6e8399;
    padding: 10px 22px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: 14px;
}
QTabBar::tab:selected {
    color: #dde8f5;
    border-bottom: 2px solid #1d6ef5;
}
QTabBar::tab:hover { color: #dde8f5; background-color: #131920; }

/* ── Tooltip ─────────────────────────────────────────────────── */
QToolTip {
    background-color: #1a2130;
    color: #dde8f5;
    border: 1px solid #253040;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 13px;
}

/* ── Frame lines ─────────────────────────────────────────────── */
QFrame[frameShape="4"],
QFrame[frameShape="5"] {
    color: #1c2530;
    border: none;
    max-width: 1px;
    max-height: 1px;
}

)";
}

} // namespace Style
