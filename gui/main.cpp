#include <QApplication>
#include <QFont>
#include <QFontDatabase>
#include <unistd.h>
#include "ui/MainWindow.h"

int main(int argc, char *argv[])
{
    /* Forward display environment when launched via sudo */
    if (qgetenv("XDG_RUNTIME_DIR").isEmpty())
        qputenv("XDG_RUNTIME_DIR",
                QByteArray("/run/user/") + QByteArray::number(getuid()));

    if (qgetenv("DISPLAY").isEmpty() && qgetenv("WAYLAND_DISPLAY").isEmpty())
        qputenv("DISPLAY", ":0");

    QApplication app(argc, argv);
    app.setApplicationName("Kernel Traffic Analyzer");
    app.setApplicationVersion("6.0");

    /*
     * Font priority: JetBrains Mono (crisp, designed for dense data)
     * → Ubuntu Mono → Consolas → system monospace.
     * JetBrains Mono is free/open-source: https://www.jetbrains.com/lp/mono/
     * Install on Ubuntu: sudo apt install fonts-jetbrains-mono
     */
    QFont appFont;
    const QStringList families = {
        "JetBrains Mono", "Ubuntu Mono", "Consolas", "Courier New"};
    for (const QString &family : families)
    {
        QFont candidate(family);
        if (candidate.exactMatch() ||
            QFontDatabase().families().contains(family))
        {
            appFont = candidate;
            break;
        }
    }
    appFont.setPixelSize(13);
    appFont.setHintingPreference(QFont::PreferFullHinting);
    app.setFont(appFont);

    MainWindow w;
    w.show();
    return app.exec();
}