#pragma once
#include <QString>
#include <QColor>
#include <QFont>

/*
 * KTA — Azure-style Clean Dark UI  v6.2
 *
 * Palette matches Azure Portal / VS Code dark theme:
 *   Base:    #1e1e1e   Main window, table bodies
 *   Panel:   #252526   Sidebar, top bars, panels, cards
 *   Raised:  #2d2d2d   Elevated cards, header rows
 *   Active:  #37373d   Active nav item bg
 *   Hover:   #2a2d2e   Row hover
 *   Select:  #094771   Selected rows (Azure blue highlight)
 *
 *   Border:  #333333   Standard dividers
 *   Border2: #3e3e42   Inputs, stronger borders
 *   Border3: #555555   Focus/hover borders
 *
 *   Text1:   #ffffff   Page titles, active labels
 *   Text2:   #cccccc   Primary body text
 *   Text3:   #8a8a8a   Secondary/muted text
 *   Text4:   #555555   Very muted, placeholders
 *
 *   Accent:  #3794ff   Blue — links, active states, focus rings
 *   Success: #4ec9b0   Teal green
 *   Warning: #ce9178   Amber/warm orange
 *   Danger:  #f44747   Red
 *   Purple:  #c586c0
 *
 *   Status:  #007acc   VS Code blue status bar
 *
 * Font: Segoe UI → Ubuntu → Arial → sans-serif
 */

namespace Style
{
    namespace Color
    {
        inline const QColor BgBase     = QColor("#1e1e1e");
        inline const QColor BgPanel    = QColor("#252526");
        inline const QColor BgRaised   = QColor("#2d2d2d");
        inline const QColor BgActive   = QColor("#37373d");
        inline const QColor BgHover    = QColor("#2a2d2e");
        inline const QColor BgSelected = QColor("#094771");

        inline const QColor Border  = QColor("#333333");
        inline const QColor Border2 = QColor("#3e3e42");
        inline const QColor Border3 = QColor("#555555");

        inline const QColor Text1 = QColor("#ffffff");
        inline const QColor Text2 = QColor("#cccccc");
        inline const QColor Text3 = QColor("#8a8a8a");
        inline const QColor Text4 = QColor("#555555");

        inline const QColor Accent  = QColor("#3794ff");
        inline const QColor Success = QColor("#4ec9b0");
        inline const QColor Warning = QColor("#ce9178");
        inline const QColor Danger  = QColor("#f44747");
        inline const QColor Purple  = QColor("#c586c0");

        inline const QColor SuccessBg = QColor("#1a2e2b");
        inline const QColor WarningBg = QColor("#2e1f15");
        inline const QColor DangerBg  = QColor("#2e1515");

        inline QColor forState(const QString &s)
        {
            if (s == "ESTABLISHED") return Success;
            if (s == "UDP_ACTIVE")  return Accent;
            if (s == "SYN_SENT")    return Warning;
            if (s == "SYN_RECV")    return Warning;
            if (s == "FIN_WAIT")    return Text3;
            return Text4;
        }
        inline QColor forRtt(double ms)
        {
            if (ms <= 0)   return Text4;
            if (ms < 50)   return Success;
            if (ms < 150)  return Warning;
            return Danger;
        }
    }

    namespace Font
    {
        inline QFont ui(int px = 14)
        {
            QFont f;
            f.setFamilies({"Segoe UI", "Ubuntu", "Arial", "sans-serif"});
            f.setPixelSize(px);
            return f;
        }
        inline QFont heading(int px = 16)
        {
            QFont f;
            f.setFamilies({"Segoe UI", "Ubuntu", "Arial", "sans-serif"});
            f.setPixelSize(px);
            f.setWeight(QFont::DemiBold);
            return f;
        }
        inline QFont mono(int px = 13)
        {
            QFont f;
            f.setFamilies({"JetBrains Mono", "Consolas", "Ubuntu Mono", "monospace"});
            f.setPixelSize(px);
            return f;
        }
    }

    inline QString globalStyleSheet()
    {
        return R"(

/* ══════════════════════════════════════════════════════════════
   KTA — Azure Dark UI  v6.2
   ══════════════════════════════════════════════════════════════ */

* {
    font-family: "Segoe UI", "Ubuntu", Arial, sans-serif;
    font-size: 14px;
    outline: none;
}

QMainWindow, QDialog {
    background-color: #1e1e1e;
}
QWidget {
    background-color: #1e1e1e;
    color: #cccccc;
    font-size: 14px;
}

/* ── Sidebar ──────────────────────────────────────────────── */
#Sidebar {
    background-color: #252526;
    border-right: 1px solid #333333;
}
#SidebarLogo {
    background-color: #252526;
    border-bottom: 1px solid #333333;
}
#SectionTitle {
    color: #555555;
    font-size: 11px;
    font-weight: 700;
    padding: 14px 16px 5px 16px;
    letter-spacing: 1.5px;
    text-transform: uppercase;
    background: transparent;
}

/* ── Nav buttons ──────────────────────────────────────────── */
QPushButton#NavButton {
    background: transparent;
    border: none;
    color: #8a8a8a;
    text-align: left;
    padding: 10px 16px;
    font-size: 14px;
    font-weight: 400;
}
QPushButton#NavButton:hover {
    background-color: #2a2d2e;
    color: #cccccc;
    border-left: 2px solid #555555;
    padding-left: 14px;
}
QPushButton#NavButton[active="true"] {
    background-color: #37373d;
    color: #ffffff;
    border-left: 2px solid #3794ff;
    padding-left: 14px;
    font-weight: 500;
}

/* ── Top bar ──────────────────────────────────────────────── */
#TopBar {
    background-color: #252526;
    border-bottom: 1px solid #333333;
    padding: 0 20px;
    min-height: 56px;
    max-height: 64px;
}

/* ── Tables ───────────────────────────────────────────────── */
QTableView, QTableWidget {
    background-color: #1e1e1e;
    alternate-background-color: #252526;
    border: none;
    gridline-color: #2a2a2a;
    selection-background-color: #094771;
    selection-color: #ffffff;
    font-size: 14px;
    show-decoration-selected: 1;
}
QTableView::item, QTableWidget::item {
    padding: 10px 14px;
    border-bottom: 1px solid #2a2a2a;
    color: #cccccc;
}
QTableView::item:selected, QTableWidget::item:selected {
    background-color: #094771;
    color: #ffffff;
}
QTableView::item:hover, QTableWidget::item:hover {
    background-color: #2a2d2e;
}
QHeaderView {
    background-color: #252526;
    border: none;
}
QHeaderView::section {
    background-color: #252526;
    color: #8a8a8a;
    font-size: 11px;
    font-weight: 700;
    padding: 10px 14px;
    border: none;
    border-bottom: 1px solid #333333;
    border-right: 1px solid #333333;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}
QHeaderView::section:hover {
    background-color: #2a2d2e;
    color: #cccccc;
}
QHeaderView::section:last { border-right: none; }
QHeaderView::section:checked {
    color: #3794ff;
}

/* ── Scrollbars ───────────────────────────────────────────── */
QScrollBar:vertical {
    background: transparent;
    width: 8px;
    border: none;
    margin: 0;
}
QScrollBar::handle:vertical {
    background: #424242;
    border-radius: 4px;
    min-height: 28px;
}
QScrollBar::handle:vertical:hover { background: #686868; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical,
QScrollBar::add-page:vertical,  QScrollBar::sub-page:vertical
{ height: 0; background: transparent; border: none; }

QScrollBar:horizontal {
    background: transparent;
    height: 8px;
    border: none;
    margin: 0;
}
QScrollBar::handle:horizontal {
    background: #424242;
    border-radius: 4px;
    min-width: 28px;
}
QScrollBar::handle:horizontal:hover { background: #686868; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal,
QScrollBar::add-page:horizontal,  QScrollBar::sub-page:horizontal
{ width: 0; background: transparent; border: none; }

/* ── Inputs ───────────────────────────────────────────────── */
QLineEdit {
    background-color: #3c3c3c;
    border: 1px solid #555555;
    border-radius: 4px;
    color: #cccccc;
    padding: 7px 12px;
    font-size: 14px;
    selection-background-color: #094771;
}
QLineEdit:focus {
    border-color: #3794ff;
}
QLineEdit:hover { border-color: #686868; }
QLineEdit::placeholder { color: #555555; }

/* ── ComboBox ─────────────────────────────────────────────── */
QComboBox {
    background-color: #3c3c3c;
    border: 1px solid #555555;
    border-radius: 4px;
    color: #cccccc;
    padding: 6px 12px;
    font-size: 14px;
    min-width: 120px;
}
QComboBox:hover  { border-color: #686868; }
QComboBox:focus  { border-color: #3794ff; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background-color: #252526;
    border: 1px solid #555555;
    color: #cccccc;
    selection-background-color: #094771;
    selection-color: #ffffff;
    padding: 4px;
    font-size: 14px;
    outline: none;
}
QComboBox QAbstractItemView::item {
    padding: 8px 12px;
    min-height: 28px;
}

/* ── Splitter ─────────────────────────────────────────────── */
QSplitter::handle           { background-color: #333333; }
QSplitter::handle:hover     { background-color: #3794ff; }
QSplitter::handle:horizontal{ width:  1px; }
QSplitter::handle:vertical  { height: 1px; }

/* ── Status bar (VS Code blue strip) ──────────────────────── */
QStatusBar {
    background-color: #007acc;
    border-top: none;
    color: #ffffff;
    font-size: 12px;
    padding: 0 16px;
    min-height: 24px;
}
QStatusBar QLabel {
    color: #ffffff;
    font-size: 12px;
    padding: 0 6px;
    background: transparent;
}

/* ── Detail panel ─────────────────────────────────────────── */
#DetailPanel {
    background-color: #252526;
    border-top: 1px solid #333333;
}

/* ── Stat cards ───────────────────────────────────────────── */
#StatCard {
    background-color: #2d2d2d;
    border: 1px solid #333333;
    border-radius: 6px;
}
#StatCard:hover {
    background-color: #333333;
    border-color: #555555;
}

/* ── List widget ──────────────────────────────────────────── */
QListWidget {
    background-color: #252526;
    border: none;
    font-size: 14px;
    outline: none;
}
QListWidget::item {
    padding: 10px 16px;
    border-bottom: 1px solid #333333;
    color: #cccccc;
}
QListWidget::item:selected {
    background-color: #094771;
    color: #ffffff;
    border-left: 2px solid #3794ff;
    padding-left: 14px;
}
QListWidget::item:hover { background-color: #2a2d2e; }

/* ── Push buttons ─────────────────────────────────────────── */
QPushButton {
    background-color: #3c3c3c;
    border: 1px solid #555555;
    border-radius: 4px;
    color: #cccccc;
    padding: 7px 16px;
    font-size: 14px;
}
QPushButton:hover {
    background-color: #505050;
    border-color: #686868;
    color: #ffffff;
}
QPushButton:pressed {
    background-color: #094771;
    border-color: #3794ff;
    color: #ffffff;
}
QPushButton:disabled {
    background-color: #2d2d2d;
    border-color: #3e3e42;
    color: #555555;
}

/* ── Tab bar ──────────────────────────────────────────────── */
QTabWidget::pane {
    border: none;
    background-color: #1e1e1e;
    border-top: 1px solid #333333;
}
QTabBar::tab {
    background: transparent;
    color: #8a8a8a;
    padding: 10px 24px;
    border: none;
    border-bottom: 2px solid transparent;
    font-size: 14px;
}
QTabBar::tab:selected {
    color: #ffffff;
    border-bottom: 2px solid #3794ff;
}
QTabBar::tab:hover {
    color: #cccccc;
    background-color: #2a2d2e;
}

/* ── Tooltip ──────────────────────────────────────────────── */
QToolTip {
    background-color: #252526;
    color: #cccccc;
    border: 1px solid #555555;
    border-radius: 4px;
    padding: 6px 10px;
    font-size: 13px;
}

/* ── Frame dividers ───────────────────────────────────────── */
QFrame[frameShape="4"],
QFrame[frameShape="5"] {
    color: #333333;
    border: none;
    max-width: 1px;
    max-height: 1px;
    background-color: #333333;
}

/* ── Menu ─────────────────────────────────────────────────── */
QMenuBar {
    background-color: #252526;
    color: #cccccc;
    border-bottom: 1px solid #333333;
    font-size: 14px;
    padding: 2px 0;
}
QMenuBar::item { padding: 5px 12px; background: transparent; border-radius: 3px; }
QMenuBar::item:selected { background-color: #37373d; color: #ffffff; }
QMenu {
    background-color: #252526;
    border: 1px solid #3e3e42;
    color: #cccccc;
    font-size: 14px;
    padding: 4px;
}
QMenu::item { padding: 8px 20px; border-radius: 3px; }
QMenu::item:selected { background-color: #094771; color: #ffffff; }
QMenu::separator { height: 1px; background-color: #333333; margin: 4px 8px; }

/* ── Progress bar ─────────────────────────────────────────── */
QProgressBar {
    background-color: #3c3c3c;
    border: none;
    border-radius: 2px;
    height: 4px;
    text-align: center;
    color: transparent;
}
QProgressBar::chunk { background-color: #3794ff; border-radius: 2px; }

/* ── CheckBox ─────────────────────────────────────────────── */
QCheckBox { color: #cccccc; font-size: 14px; spacing: 8px; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid #555555;
    border-radius: 3px;
    background-color: #3c3c3c;
}
QCheckBox::indicator:hover { border-color: #3794ff; }
QCheckBox::indicator:checked { background-color: #3794ff; border-color: #3794ff; }

/* ── GroupBox ─────────────────────────────────────────────── */
QGroupBox {
    border: 1px solid #333333;
    border-radius: 6px;
    margin-top: 16px;
    padding-top: 8px;
    color: #8a8a8a;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    text-transform: uppercase;
}
QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    left: 12px;
    color: #555555;
    font-size: 11px;
}

/* ── Graphics views ───────────────────────────────────────── */
QGraphicsView {
    background-color: #1a1a1a;
    border: none;
}

/* ── Dock widgets ─────────────────────────────────────────── */
QDockWidget { color: #cccccc; font-size: 14px; }
QDockWidget::title {
    background-color: #252526;
    padding: 8px 12px;
    border-bottom: 1px solid #333333;
    color: #8a8a8a;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

/* ── Message box ──────────────────────────────────────────── */
QMessageBox { background-color: #252526; }
QMessageBox QLabel { color: #cccccc; font-size: 14px; }
QMessageBox QPushButton { min-width: 88px; padding: 8px 20px; }

/* ── Spin / Double spin ───────────────────────────────────── */
QSpinBox, QDoubleSpinBox {
    background-color: #3c3c3c;
    border: 1px solid #555555;
    border-radius: 4px;
    color: #cccccc;
    padding: 6px 10px;
    font-size: 14px;
}
QSpinBox:focus, QDoubleSpinBox:focus { border-color: #3794ff; }

/* ── Slider ───────────────────────────────────────────────── */
QSlider::groove:horizontal {
    height: 4px; background: #3c3c3c; border-radius: 2px;
}
QSlider::handle:horizontal {
    background: #3794ff; border: none;
    width: 14px; height: 14px;
    margin: -5px 0; border-radius: 7px;
}
QSlider::sub-page:horizontal { background: #3794ff; border-radius: 2px; }

)";
    }

} // namespace Style
