/**
 * @file RoutesTab.cpp
 * @brief Implementation of the traceroute tab.
 * @details Creates a route tree view and writes validated IPv4 traceroute requests to the kernel pending proc endpoint.
 * @author Kernel Traffic Analyzer Project
 * @license MIT
 */
#include "tabs/RoutesTab.h"

#include <QFile>
#include <QHeaderView>
#include <QHostAddress>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QTreeView>
#include <QVBoxLayout>

RoutesTab::RoutesTab(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void RoutesTab::setRoutes(const QVector<RouteRecord>& records)
{
    route_model_->setData(records);
    tree_->expandAll();
}

void RoutesTab::requestTraceroute()
{
    const QString ip = ip_edit_->text().trimmed();
    QHostAddress address;
    if (!address.setAddress(ip) || address.protocol() != QAbstractSocket::IPv4Protocol) {
        QMessageBox::warning(this, "Invalid IP", "Enter a valid IPv4 address.");
        return;
    }
    QFile file("/proc/traffic_analyzer_routes_pending");
    if (!file.open(QIODevice::WriteOnly | QIODevice::Append | QIODevice::Text)) {
        QMessageBox::warning(this, "Traceroute Failed", "Could not write traceroute request.");
        return;
    }
    file.write(QString("%1\n").arg(ip).toUtf8());
    QMessageBox::information(this, "Traceroute Requested", QString("Traceroute requested for %1.").arg(ip));
}

void RoutesTab::setupUi()
{
    auto* root = new QVBoxLayout(this);
    root->setContentsMargins(12, 12, 12, 12);
    root->setSpacing(10);

    auto* header = new QHBoxLayout();
    auto* title = new QLabel("Traceroute Map", this);
    ip_edit_ = new QLineEdit(this);
    ip_edit_->setPlaceholderText("IP to trace");
    auto* button = new QPushButton("Request Traceroute", this);
    header->addWidget(title);
    header->addStretch(1);
    header->addWidget(ip_edit_);
    header->addWidget(button);
    root->addLayout(header);

    route_model_ = new RouteModel(this);
    tree_ = new QTreeView(this);
    tree_->setModel(route_model_);
    tree_->setRootIsDecorated(true);
    tree_->setHeaderHidden(false);
    tree_->setAlternatingRowColors(true);
    tree_->setColumnWidth(RouteModel::ColTargetHop, 150);
    tree_->setColumnWidth(RouteModel::ColDomain, 200);
    tree_->setColumnWidth(RouteModel::ColHopNum, 50);
    tree_->setColumnWidth(RouteModel::ColHopIp, 130);
    tree_->setColumnWidth(RouteModel::ColRtt, 70);
    tree_->setColumnWidth(RouteModel::ColCountry, 80);
    tree_->setColumnWidth(RouteModel::ColAsn, 100);
    tree_->setColumnWidth(RouteModel::ColOrg, 200);
    root->addWidget(tree_, 1);

    connect(button, &QPushButton::clicked, this, &RoutesTab::requestTraceroute);
    connect(ip_edit_, &QLineEdit::returnPressed, this, &RoutesTab::requestTraceroute);
}
