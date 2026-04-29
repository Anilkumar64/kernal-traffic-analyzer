#include <QApplication>
#include <unistd.h>
#include "ui/MainWindow.h"
#include "ui/Style.h"

int main(int argc, char *argv[])
{
    if (qgetenv("XDG_RUNTIME_DIR").isEmpty())
        qputenv("XDG_RUNTIME_DIR", QByteArray("/run/user/") + QByteArray::number(getuid()));
    if (qgetenv("DISPLAY").isEmpty() && qgetenv("WAYLAND_DISPLAY").isEmpty())
        qputenv("DISPLAY", ":0");

    QApplication app(argc, argv);
    app.setApplicationName("Kernel Traffic Analyzer");
    app.setApplicationVersion("1.0");
    Style::apply(app);

    MainWindow window;
    window.show();
    return app.exec();
}
