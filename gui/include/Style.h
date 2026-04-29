/**
 * @file Style.h
 * @brief Shared color and formatting helpers for the Qt GUI.
 * @details Centralizes the Kernel Traffic Analyzer palette and small display-formatting utilities used by models, delegates, and status widgets.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include <QColor>
#include <QString>

/**
 * @brief Named colors used by the Kernel Traffic Analyzer interface.
 */
namespace KtaColors {
constexpr const char* BgBase      = "#0d1117";
constexpr const char* BgSurface   = "#161b22";
constexpr const char* BgElevated  = "#21262d";
constexpr const char* Accent      = "#238636";
constexpr const char* Warning     = "#e3b341";
constexpr const char* Danger      = "#f85149";
constexpr const char* Purple      = "#8b5cf6";
constexpr const char* Blue        = "#58a6ff";
constexpr const char* Teal        = "#39d353";
constexpr const char* Gray        = "#6e7681";
constexpr const char* TextPrimary = "#e6edf3";
constexpr const char* TextMuted   = "#8b949e";
constexpr const char* Border      = "#30363d";
}

/**
 * @brief Returns the display color associated with a network state.
 * @param state State string from the kernel proc file.
 * @return QColor from the KTA palette.
 */
inline QColor stateColor(const QString& state)
{
    const QString normalized = state.trimmed().toUpper();
    if (normalized == "ESTABLISHED") {
        return QColor(KtaColors::Accent);
    }
    if (normalized == "SYN_SENT" || normalized == "SYN_RECEIVED" || normalized == "SYN_RECV" || normalized == "SYN") {
        return QColor(KtaColors::Warning);
    }
    if (normalized == "CLOSED") {
        return QColor(KtaColors::Danger);
    }
    if (normalized == "FIN_WAIT") {
        return QColor(KtaColors::Purple);
    }
    if (normalized == "TIME_WAIT") {
        return QColor(KtaColors::Blue);
    }
    if (normalized == "UDP" || normalized == "UDP_ACTIVE") {
        return QColor(KtaColors::Teal);
    }
    return QColor(KtaColors::Gray);
}

/**
 * @brief Returns the display color associated with an anomaly severity.
 * @param severity Severity label such as WARNING or CRITICAL.
 * @return QColor from the KTA palette.
 */
inline QColor severityColor(const QString& severity)
{
    const QString normalized = severity.trimmed().toUpper();
    if (normalized == "CRITICAL") {
        return QColor(KtaColors::Danger);
    }
    if (normalized == "WARNING") {
        return QColor(KtaColors::Warning);
    }
    return QColor(KtaColors::Gray);
}

/**
 * @brief Formats a byte count using binary units.
 * @param bytes Raw byte count.
 * @return Human-readable size string.
 */
inline QString formatBytes(quint64 bytes)
{
    static const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 4) {
        value /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        return QString("%1 %2").arg(bytes).arg(units[unit]);
    }
    return QString("%1 %2").arg(value, 0, 'f', 2).arg(units[unit]);
}

/**
 * @brief Formats a byte-per-second value using binary units.
 * @param bytesPerSec Raw byte rate.
 * @return Human-readable rate string.
 */
inline QString formatRate(quint64 bytesPerSec)
{
    return QString("%1/s").arg(formatBytes(bytesPerSec));
}
