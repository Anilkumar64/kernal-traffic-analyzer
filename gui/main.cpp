#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include "ui/MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("Kernel Traffic Analyzer");
    app.setApplicationVersion("6.0");

    // Ubuntu Mono 15px — bigger, sharper, more readable
    QFont f("Ubuntu Mono");
    f.setPixelSize(15);
    f.setHintingPreference(QFont::PreferFullHinting);
    app.setFont(f);

    MainWindow w;
    w.show();
    return app.exec();
}
