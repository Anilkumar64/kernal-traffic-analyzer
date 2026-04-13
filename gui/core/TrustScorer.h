#pragma once
#include <QObject>
#include <QMap>
#include <QString>
#include <QColor>
#include <QStringList>
#include <QVector>
#include <QMutex>

// Forward declarations
struct ProcEntry;
struct TrafficEntry;

struct TrustScore
{
    QString process;
    int score = 50; // 0-100
    QString grade;  // A/B/C/D/F
    QColor color;
    QStringList reasons;
};

enum class TrustLevel
{
    Unknown = 0,
    Trusted = 1,
    Neutral = 2,
    Suspicious = 3,
    Blocked = 4
};

struct TrustEntry
{
    QString process;
    TrustLevel level = TrustLevel::Unknown;
    int score = 50;
    QString reason;
    bool manual = false;
};

class TrustScorer : public QObject
{
    Q_OBJECT
public:
    static TrustScorer &instance();

    TrustScore score(const ProcEntry &proc,
                     const QVector<TrafficEntry> &conns) const;

    TrustLevel getLevel(const QString &process) const;
    void setLevel(const QString &process, TrustLevel level,
                  const QString &reason = {});
    TrustEntry getEntry(const QString &process) const;
    QList<TrustEntry> allEntries() const;
    static QString labelForLevel(TrustLevel l);

signals:
    void trustChanged(const QString &process);

private:
    TrustScorer() = default;
    QMap<QString, TrustEntry> m_entries;
    mutable QMutex m_entriesMutex;
};
