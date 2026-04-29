/**
 * @file main.cpp
 * @brief Application entry point for the Kernel Traffic Analyzer GUI.
 * @details Creates QApplication, applies the preferred font, and shows the main Qt6 desktop window.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "MainWindow.h"

#include <QApplication>
#include <QFont>

/**
 * @brief Starts the Qt application.
 * @param argc Argument count.
 * @param argv Argument values.
 * @return Qt event loop result.
 */
int main(int argc, char* argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("Kernel Traffic Analyzer");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("KTA Project");
    QFont font = app.font();
    font.setFamily("Inter");
    font.setPointSize(10);
    app.setFont(font);
    MainWindow window;
    window.setWindowTitle("Kernel Traffic Analyzer");
    window.resize(1400, 900);
    window.setMinimumSize(900, 600);
    window.show();
    return app.exec();
}
