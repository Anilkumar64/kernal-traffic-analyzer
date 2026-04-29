#pragma once
#include <QApplication>
#include <QFont>

namespace Style {
inline void apply(QApplication &app)
{
    QFont font;
    font.setFamilies({"Segoe UI", "Ubuntu", "Arial"});
    font.setPixelSize(13);
    app.setFont(font);
    app.setStyleSheet(R"(
        QMainWindow, QWidget { background:#1c1c1c; color:#e0e0e0; }
        QMenuBar, QMenu { background:#242428; color:#e0e0e0; border:1px solid #323236; }
        QMenuBar::item:selected, QMenu::item:selected { background:#2c2c30; }
        QLineEdit, QSpinBox { background:#242428; color:#e0e0e0; border:1px solid #323236; padding:6px; }
        QLineEdit:focus, QSpinBox:focus { border-color:#4a9eff; }
        QPushButton { background:#2c2c30; color:#e0e0e0; border:1px solid #323236; padding:7px 10px; }
        QPushButton:hover { background:#242428; }
        QCheckBox, QTabBar::tab { color:#e0e0e0; }
        QTabBar::tab { background:#242428; padding:7px 14px; border:1px solid #323236; }
        QTabBar::tab:selected { background:#2c2c30; border-bottom-color:#4a9eff; }
        QTableView { background:#1c1c1c; alternate-background-color:#212125; color:#e0e0e0;
                     border:1px solid #323236; gridline-color:#1c1c1c; selection-background-color:#1a3a5c; }
        QHeaderView::section { background:#242428; color:#707070; border:0; padding:7px; font-size:11px; }
        QStatusBar { background:#005f99; color:#ffffff; }
        QSplitter::handle { background:#323236; }
    )");
}
}
