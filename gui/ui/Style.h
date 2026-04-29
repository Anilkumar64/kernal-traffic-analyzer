#pragma once

#include <QApplication>
#include <QColor>
#include <QFont>
#include <QString>

namespace KtaColors {
inline const QColor BgVoid    { 0x0d, 0x0d, 0x0f };
inline const QColor BgBase    { 0x11, 0x11, 0x13 };
inline const QColor BgSurface { 0x17, 0x17, 0x1a };
inline const QColor BgRaised  { 0x1e, 0x1e, 0x22 };
inline const QColor BgHover   { 0x22, 0x22, 0x28 };
inline const QColor BgCard    { 0x1a, 0x1a, 0x1e };
inline const QColor BgAlt     { 0x21, 0x21, 0x25 };
inline const QColor Selection { 0x1a, 0x3a, 0x5c };

inline const QColor Border   { 0x26, 0x26, 0x2e };
inline const QColor BorderMd { 0x2e, 0x2e, 0x38 };
inline const QColor BorderHi { 0x3a, 0x3a, 0x48 };

inline const QColor Text1 { 0xf0, 0xf0, 0xf5 };
inline const QColor Text2 { 0xb0, 0xb0, 0xc0 };
inline const QColor Text3 { 0x70, 0x70, 0x85 };
inline const QColor Text4 { 0x40, 0x40, 0x50 };

inline const QColor Accent  { 0x5b, 0x8d, 0xee };
inline const QColor AccentD { 0x1a, 0x2a, 0x4a };

inline const QColor Teal   { 0x3e, 0xcf, 0xb0 };
inline const QColor TealD  { 0x0d, 0x2e, 0x29 };
inline const QColor Amber  { 0xe8, 0xa4, 0x4a };
inline const QColor AmberD { 0x2e, 0x1f, 0x08 };
inline const QColor Red    { 0xe0, 0x55, 0x55 };
inline const QColor RedD   { 0x2e, 0x0f, 0x0f };
inline const QColor Purple { 0x9b, 0x7d, 0xea };
inline const QColor Green  { 0x52, 0xc9, 0x7a };

inline const QColor StatusBar { 0x0a, 0x5a, 0x9a };
inline const QColor StatusDot { 0x4e, 0xff, 0x9a };
}

inline QFont uiFont(int px = 13, int weight = QFont::Normal)
{
    QFont f;
    f.setFamilies({"IBM Plex Sans", "Ubuntu", "Segoe UI", "Arial"});
    f.setPixelSize(px);
    f.setWeight(static_cast<QFont::Weight>(weight));
    return f;
}

inline QFont monoFont(int px = 12)
{
    QFont f;
    f.setFamilies({"IBM Plex Mono", "JetBrains Mono", "Consolas", "Ubuntu Mono"});
    f.setPixelSize(px);
    return f;
}

namespace Style {
inline QString css(const QColor &color) { return color.name(QColor::HexRgb); }
inline QString rgba(const QColor &color, double alpha)
{
    return QString("rgba(%1,%2,%3,%4)")
        .arg(color.red()).arg(color.green()).arg(color.blue()).arg(alpha);
}

inline const QString KTA_QSS = R"(
QWidget {
    background-color: #111113;
    color: #b0b0c0;
    font-family: 'IBM Plex Sans', Ubuntu, Arial;
    font-size: 13px;
}
QMenuBar {
    background: #17171a;
    color: #b0b0c0;
    border: none;
    border-bottom: 1px solid #26262e;
    padding-left: 8px;
}
QMenuBar::item {
    background: transparent;
    padding: 5px 10px;
}
QMenuBar::item:selected {
    background: #222228;
    color: #f0f0f5;
}
QMenu {
    background: #17171a;
    color: #b0b0c0;
    border: 1px solid #2e2e38;
    padding: 4px;
}
QMenu::item {
    padding: 6px 22px;
    background: transparent;
}
QMenu::item:selected {
    background: #222228;
    color: #f0f0f5;
}
QLineEdit {
    background: #1e1e22;
    color: #f0f0f5;
    border: 1px solid #2e2e38;
    border-radius: 6px;
    padding: 6px 12px 6px 32px;
    selection-background-color: #1a3a5c;
}
QLineEdit:focus {
    border-color: #5b8dee;
}
QPushButton {
    background: #1e1e22;
    color: #b0b0c0;
    border: 1px solid #2e2e38;
    border-radius: 6px;
    padding: 6px 10px;
}
QPushButton:hover {
    background: #222228;
    color: #f0f0f5;
}
QTableView, QTreeView {
    background: #111113;
    alternate-background-color: #212125;
    color: #b0b0c0;
    border: none;
    gridline-color: #111113;
    selection-background-color: #1a3a5c;
    selection-color: #f0f0f5;
}
QHeaderView::section {
    background: #17171a;
    color: #707085;
    border: none;
    border-bottom: 1px solid #26262e;
    padding: 8px 10px;
    font-size: 10px;
    font-weight: 600;
}
QScrollBar:vertical {
    background: transparent; width: 5px; border: none;
}
QScrollBar::handle:vertical {
    background: #3a3a48; border-radius: 2px; min-height: 20px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar:horizontal {
    background: transparent; height: 5px; border: none;
}
QScrollBar::handle:horizontal {
    background: #3a3a48; border-radius: 2px;
}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0; }
QSplitter::handle { background: #2e2e38; }
QSplitter::handle:hover { background: #3a3a48; }
QToolTip {
    background: #1e1e22; color: #f0f0f5;
    border: 1px solid #2e2e38; padding: 4px 8px;
    font-size: 11px;
}
)";

inline void apply(QApplication &app)
{
    app.setFont(uiFont());
    app.setStyleSheet(KTA_QSS);
}
}
