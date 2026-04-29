/**
 * @file Exporter.h
 * @brief JSON and CSV export utilities.
 * @details Provides modal file/directory pickers and serializes current live KTA data without external dependencies.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#pragma once

#include "ProcReader.h"

#include <QWidget>

/**
 * @brief Static export helpers for current GUI data.
 */
class Exporter {
public:
    /** @brief Exports a full ParsedData snapshot to JSON. @param data Current data. @param parent Dialog parent. */
    static void exportJson(const ParsedData& data, QWidget* parent);
    /** @brief Exports current tables to four CSV files. @param data Current data. @param parent Dialog parent. */
    static void exportCsv(const ParsedData& data, QWidget* parent);

private:
    /** @brief Encodes connections as JSON. @param recs Records. @return JSON text. */
    static QString connectionsToJson(const QVector<ConnectionRecord>& recs);
    /** @brief Encodes processes as JSON. @param recs Records. @return JSON text. */
    static QString procsToJson(const QVector<ProcRecord>& recs);
    /** @brief Encodes connections as CSV. @param recs Records. @return CSV text. */
    static QString connectionsToCsv(const QVector<ConnectionRecord>& recs);
    /** @brief Encodes processes as CSV. @param recs Records. @return CSV text. */
    static QString procsToCsv(const QVector<ProcRecord>& recs);
    /** @brief Encodes DNS rows as CSV. @param recs Records. @return CSV text. */
    static QString dnsToCsv(const QVector<DnsRecord>& recs);
    /** @brief Encodes anomaly rows as CSV. @param recs Records. @return CSV text. */
    static QString anomaliesToCsv(const QVector<AnomalyRecord>& recs);
};
