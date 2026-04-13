#pragma once
#include <QString>
#include <QColor>
#include <QFont>

namespace Style
{

    namespace Color
    {
        /* ── Light cute palette ─────────────────────────────────── */
        inline const QColor BgDeep = QColor("#f0f2f5");
        inline const QColor BgBase = QColor("#ffffff");
        inline const QColor BgSurface = QColor("#f7f8fa");
        inline const QColor BgCard = QColor("#ffffff");
        inline const QColor BgHover = QColor("#eef1f6");
        inline const QColor BgSelected = QColor("#e0ecff");
        inline const QColor BorderDim = QColor("#e4e8ee");
        inline const QColor Border = QColor("#d0d7e0");
        inline const QColor BorderLight = QColor("#b8c4d0");
        inline const QColor TextPrimary = QColor("#1e2a3a");
        inline const QColor TextSecond = QColor("#5c6b7f");
        inline const QColor TextMuted = QColor("#9ba8b6");
        inline const QColor TextLink = QColor("#6366f1");
        inline const QColor AccentBlue = QColor("#6366f1");
        inline const QColor Success = QColor("#10b981");
        inline const QColor SuccessBg = QColor("#ecfdf5");
        inline const QColor Warning = QColor("#f59e0b");
        inline const QColor WarningBg = QColor("#fffbeb");
        inline const QColor Danger = QColor("#ef4444");
        inline const QColor DangerBg = QColor("#fef2f2");

        inline QColor forState(const QString &s)
        {
            if (s == "ESTABLISHED")
                return Success;
            if (s == "UDP_ACTIVE")
                return QColor("#06b6d4");
            if (s == "SYN_SENT")
                return Warning;
            if (s == "SYN_RECV")
                return Warning;
            if (s == "FIN_WAIT")
                return TextSecond;
            return TextMuted;
        }
        inline QColor forRtt(double ms)
        {
            if (ms <= 0)
                return TextMuted;
            if (ms < 50)
                return Success;
            if (ms < 150)
                return Warning;
            return Danger;
        }
    }

    namespace Font
    {
        inline QFont mono(int px = 14)
        {
            QFont f("Ubuntu Mono");
            f.setPixelSize(px);
            return f;
        }
        inline QFont heading(int px = 16)
        {
            QFont f("Ubuntu Mono");
            f.setPixelSize(px);
            f.setWeight(QFont::Medium);
            return f;
        }
    }

    inline QString globalStyleSheet()
    {
        return R"(

/* ── Reset ───────────────────────────────────────────────────── */
* { font-family: "Ubuntu Mono"; outline: none; }

/* ── Base ────────────────────────────────────────────────────── */
QMainWindow {
    background-color: #f0f2f5;
}
QWidget {
    background-color: #ffffff;
    color: #1e2a3a;
    font-family: "Ubuntu Mono";
    font-size: 14px;
}

/* ── Sidebar ─────────────────────────────────────────────────── */
#Sidebar {
    background-color: #f7f8fa;
    border-right: 1px solid #e4e8ee;
}
#SidebarLogo {
    background-color: #f7f8fa;
    border-bottom: 1px solid #e4e8ee;
}
#SectionTitle {
    color: #9ba8b6;
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
    color: #5c6b7f;
    text-align: left;
    padding: 11px 18px;
    font-size: 14px;
    font-weight: 400;
}
QPushButton#NavButton:hover {
    background-color: #eef1f6;
    color: #1e2a3a;
}
QPushButton#NavButton[active="true"] {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #e0ecff, stop:1 #ffffff);
    color: #6366f1;
    border-left: 3px solid #6366f1;
    padding-left: 15px;
    font-weight: 600;
}

/* ── Top bar ─────────────────────────────────────────────────── */
#TopBar {
    background-color: #f7f8fa;
    border-bottom: 1px solid #e4e8ee;
    padding: 0 20px;
    min-height: 58px;
    max-height: 58px;
}

/* ── Tables ──────────────────────────────────────────────────── */
QTableView, QTableWidget {
    background-color: #ffffff;
    alternate-background-color: #f7f8fa;
    border: none;
    gridline-color: #e4e8ee;
    selection-background-color: #e0ecff;
    selection-color: #1e2a3a;
    font-size: 14px;
    font-family: "Ubuntu Mono";
}
QTableView::item, QTableWidget::item {
    padding: 7px 14px;
    border-bottom: 1px solid #eef1f6;
}
QTableView::item:selected, QTableWidget::item:selected {
    background-color: #e0ecff;
}
QTableView::item:hover, QTableWidget::item:hover {
    background-color: #eef1f6;
}
QHeaderView { background-color: #f7f8fa; border: none; }
QHeaderView::section {
    background-color: #f7f8fa;
    color: #9ba8b6;
    font-size: 11px;
    font-weight: 700;
    padding: 9px 14px;
    border: none;
    border-bottom: 1px solid #e4e8ee;
    letter-spacing: 1.5px;
}
QHeaderView::section:hover {
    background-color: #eef1f6;
    color: #5c6b7f;
}

/* ── Scrollbars ──────────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent; width: 6px; border: none;
}
QScrollBar::handle:vertical {
    background: #d0d7e0; border-radius: 3px; min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #b8c4d0; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical
{ height:0; background:transparent; border:none; }

QScrollBar:horizontal {
    background: transparent; height: 6px; border: none;
}
QScrollBar::handle:horizontal {
    background: #d0d7e0; border-radius: 3px; min-width: 30px;
}
QScrollBar::handle:horizontal:hover { background: #b8c4d0; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal
{ width:0; background:transparent; border:none; }

/* ── Inputs ──────────────────────────────────────────────────── */
QLineEdit {
    background-color: #f7f8fa;
    border: 1px solid #d0d7e0;
    border-radius: 10px;
    color: #1e2a3a;
    padding: 8px 14px;
    font-size: 14px;
    selection-background-color: #e0ecff;
}
QLineEdit:focus {
    border-color: #6366f1;
    background-color: #ffffff;
}
QLineEdit:hover { border-color: #b8c4d0; }

/* ── ComboBox ────────────────────────────────────────────────── */
QComboBox {
    background-color: #f7f8fa;
    border: 1px solid #d0d7e0;
    border-radius: 10px;
    color: #1e2a3a;
    padding: 8px 14px;
    font-size: 14px;
    min-width: 130px;
}
QComboBox:hover { border-color: #b8c4d0; }
QComboBox:focus { border-color: #6366f1; }
QComboBox::drop-down { border:none; width:24px; }
QComboBox QAbstractItemView {
    background-color: #ffffff;
    border: 1px solid #d0d7e0;
    border-radius: 10px;
    color: #1e2a3a;
    selection-background-color: #e0ecff;
    selection-color: #6366f1;
    padding: 4px;
    font-size: 14px;
}
QComboBox QAbstractItemView::item {
    padding: 8px 14px;
    border-radius: 6px;
    min-height: 28px;
}

/* ── Splitter ────────────────────────────────────────────────── */
QSplitter::handle { background-color: #e4e8ee; }
QSplitter::handle:hover { background-color: #d0d7e0; }

/* ── Status bar ──────────────────────────────────────────────── */
QStatusBar {
    background-color: #f7f8fa;
    border-top: 1px solid #e4e8ee;
    color: #9ba8b6;
    font-size: 12px;
    padding: 0 16px;
    min-height: 28px;
}
QStatusBar QLabel {
    color: #9ba8b6;
    font-size: 12px;
    padding: 0 6px;
}

/* ── Detail panel ────────────────────────────────────────────── */
#DetailPanel {
    background-color: #f7f8fa;
    border-top: 1px solid #e4e8ee;
}

/* ── Stat cards ──────────────────────────────────────────────── */
#StatCard {
    background-color: #ffffff;
    border: 1px solid #e4e8ee;
    border-radius: 14px;
}
#StatCard:hover {
    background-color: #f7f8fa;
    border-color: #d0d7e0;
}

/* ── List widget ─────────────────────────────────────────────── */
QListWidget {
    background-color: #ffffff;
    border: none;
    font-size: 14px;
    outline: none;
}
QListWidget::item {
    padding: 11px 16px;
    border-bottom: 1px solid #eef1f6;
}
QListWidget::item:selected {
    background-color: #e0ecff;
    color: #6366f1;
    border-left: 3px solid #6366f1;
    padding-left: 13px;
}
QListWidget::item:hover { background-color: #eef1f6; }

/* ── Push buttons ────────────────────────────────────────────── */
QPushButton {
    background-color: #f7f8fa;
    border: 1px solid #d0d7e0;
    border-radius: 10px;
    color: #1e2a3a;
    padding: 8px 18px;
    font-size: 14px;
}
QPushButton:hover {
    background-color: #eef1f6;
    border-color: #b8c4d0;
}
QPushButton:pressed { background-color: #e0ecff; }

/* ── Tab bar ─────────────────────────────────────────────────── */
QTabWidget::pane { border: none; background-color: #ffffff; }
QTabBar::tab {
    background: transparent;
    color: #5c6b7f;
    padding: 10px 22px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: 14px;
}
QTabBar::tab:selected {
    color: #1e2a3a;
    border-bottom: 2px solid #6366f1;
}
QTabBar::tab:hover { color: #1e2a3a; background-color: #eef1f6; }

/* ── Tooltip ─────────────────────────────────────────────────── */
QToolTip {
    background-color: #ffffff;
    color: #1e2a3a;
    border: 1px solid #d0d7e0;
    border-radius: 10px;
    padding: 8px 12px;
    font-size: 13px;
}

/* ── Frame lines ─────────────────────────────────────────────── */
QFrame[frameShape="4"],
QFrame[frameShape="5"] {
    color: #e4e8ee;
    border: none;
    max-width: 1px;
    max-height: 1px;
}

)";
    }

} // namespace Style
