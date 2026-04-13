#include "ProcessDetailOverlay.h"
#include "Style.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QFrame>
#include <QPainter>
#include <QPainterPath>
#include <QKeyEvent>
#include <QResizeEvent>
#include <QDateTime>
#include <QHeaderView>
#include <QGraphicsLineItem>
#include <QGraphicsPolygonItem>
#include <QGraphicsEllipseItem>
#include <QGraphicsTextItem>
#include <QGraphicsPathItem>
#include <QScrollBar>
#include <QtMath>

// ================================================================
// BwGraph
// ================================================================
ProcBwGraph::ProcBwGraph(QWidget *parent) : QWidget(parent)
{
    setFixedHeight(110);
    setMinimumWidth(300);
    setStyleSheet("background:#1e1e1e;border-radius:4px;");
}

void ProcBwGraph::addSample(quint32 out, quint32 in)
{
    if (m_out.size() >= MAX) m_out.removeFirst();
    if (m_in.size()  >= MAX) m_in.removeFirst();
    m_out.append(out);
    m_in.append(in);
    quint32 pk = 1;
    for (auto v : m_out) pk = qMax(pk, v);
    for (auto v : m_in)  pk = qMax(pk, v);
    m_peak = pk;
    update();
}

void ProcBwGraph::clear()
{
    m_out.clear(); m_in.clear(); m_peak=1; update();
}

QString ProcBwGraph::fmtRate(quint32 bps) const {
    if (bps<1024)    return QString("%1 B/s").arg(bps);
    if (bps<1048576) return QString("%1 KB/s").arg(bps/1024.0,0,'f',1);
    return           QString("%1 MB/s").arg(bps/1048576.0,0,'f',1);
}

void ProcBwGraph::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing);
    QRect r = rect();
    p.fillRect(r, QColor("#252526"));

    p.setPen(QPen(QColor("#3e3e42"),1,Qt::DotLine));
    for (int i=1;i<4;++i) {
        int y = r.top()+r.height()*i/4;
        p.drawLine(r.left(),y,r.right(),y);
    }

    if (m_out.isEmpty()) {
        QFont f("Ubuntu Mono"); f.setPixelSize(12);
        p.setFont(f); p.setPen(QColor("#555555"));
        p.drawText(r,Qt::AlignCenter,"Collecting data...");
        return;
    }

    auto drawLine=[&](const QVector<quint32>&data, const QColor&color){
        if (data.isEmpty()) return;
        QPainterPath path;
        double xStep = r.width()/double(qMax(1,MAX-1));
        int off = MAX-data.size();
        bool first=true;
        for (int i=0;i<data.size();++i) {
            double x=r.left()+(off+i)*xStep;
            double y=r.bottom()-(data[i]/double(m_peak))*r.height();
            y=qBound(double(r.top()),y,double(r.bottom()));
            if(first){path.moveTo(x,y);first=false;}
            else path.lineTo(x,y);
        }
        QPainterPath fill=path;
        fill.lineTo(r.left()+(off+data.size()-1)*xStep,r.bottom());
        fill.lineTo(r.left()+off*xStep,r.bottom());
        fill.closeSubpath();
        QColor fc=color; fc.setAlpha(25);
        p.fillPath(fill,fc);
        p.setPen(QPen(color,1.5));
        p.drawPath(path);
    };
    drawLine(m_out,QColor("#6366f1"));
    drawLine(m_in, QColor("#10b981"));

    QFont lf("Ubuntu Mono"); lf.setPixelSize(11); p.setFont(lf);
    if (!m_out.isEmpty()) {
        p.setPen(QColor("#6366f1"));
        p.drawText(QRect(r.left()+6,r.top()+4,120,16),
                   Qt::AlignLeft,"OUT "+fmtRate(m_out.last()));
    }
    if (!m_in.isEmpty()) {
        p.setPen(QColor("#10b981"));
        p.drawText(QRect(r.left()+6,r.top()+20,120,16),
                   Qt::AlignLeft,"IN  "+fmtRate(m_in.last()));
    }
    p.setPen(QColor("#8a8a8a"));
    p.drawText(QRect(r.right()-100,r.top()+4,96,16),
               Qt::AlignRight,"peak "+fmtRate(m_peak));
}

// ================================================================
// ProcessDetailOverlay
// ================================================================
ProcessDetailOverlay::ProcessDetailOverlay(QWidget *parent)
    : QWidget(parent)
{
    setVisible(false);
    buildLayout();
}

void ProcessDetailOverlay::buildLayout()
{
    // Full overlay layout
    auto *outerLay = new QVBoxLayout(this);
    outerLay->setContentsMargins(0,0,0,0);
    outerLay->setSpacing(0);

    // Card — will be repositioned in resizeEvent
    m_card = new QWidget(this);
    m_card->setStyleSheet(
        "QWidget#OverlayCard{"
        "background:#1e1e1e;"
        "border:1px solid #555555;"
        "border-radius:12px;}");
    m_card->setObjectName("OverlayCard");

    auto *cardLay = new QVBoxLayout(m_card);
    cardLay->setContentsMargins(0,0,0,0);
    cardLay->setSpacing(0);

    // Header
    auto *hdr = new QWidget(m_card);
    hdr->setFixedHeight(64);
    hdr->setStyleSheet(
        "background:#1e1e1e;"
        "border-radius:12px 12px 0 0;"
        "border-bottom:1px solid #555555;");
    auto *hl = new QHBoxLayout(hdr);
    hl->setContentsMargins(20,0,16,0);

    auto *icon = new QLabel("⬡", hdr);
    icon->setStyleSheet("color:#6366f1;font-size:22px;background:transparent;");

    auto *nc = new QVBoxLayout(); nc->setSpacing(2);
    m_procName = new QLabel("", hdr);
    m_procName->setStyleSheet(
        "color:#cccccc;font-size:17px;font-weight:700;"
        "font-family:'Ubuntu Mono';background:transparent;");
    m_exePath = new QLabel("", hdr);
    m_exePath->setStyleSheet(
        "color:#8a8a8a;font-size:11px;"
        "font-family:'Ubuntu Mono';background:transparent;");
    nc->addWidget(m_procName);
    nc->addWidget(m_exePath);

    m_pidLabel = new QLabel("", hdr);
    m_pidLabel->setStyleSheet(
        "color:#8a8a8a;font-size:14px;"
        "font-family:'Ubuntu Mono';background:transparent;");

    auto *closeBtn = new QPushButton("✕", hdr);
    closeBtn->setFixedSize(32,32);
    closeBtn->setStyleSheet(
        "QPushButton{background:#3e3e42;border:none;border-radius:8px;"
        "color:#8a8a8a;font-size:14px;}"
        "QPushButton:hover{background:#ef4444;color:#cccccc;}");
    connect(closeBtn, &QPushButton::clicked, this, [this](){
        hide(); emit closed();
    });

    hl->addWidget(icon); hl->addSpacing(10);
    hl->addLayout(nc,1);
    hl->addWidget(m_pidLabel); hl->addSpacing(12);
    hl->addWidget(closeBtn);
    cardLay->addWidget(hdr);

    // Scroll area
    m_scroll = new QScrollArea(m_card);
    m_scroll->setWidgetResizable(true);
    m_scroll->setFrameShape(QFrame::NoFrame);
    m_scroll->setStyleSheet("background:#1e1e1e;border:none;");

    auto *content = new QWidget(m_scroll);
    content->setStyleSheet("background:#1e1e1e;");
    auto *cl = new QVBoxLayout(content);
    cl->setContentsMargins(20,16,20,20);
    cl->setSpacing(16);

    auto mkSec=[&](const QString&t){
        auto*l=new QLabel(t,content);
        l->setStyleSheet("color:#8a8a8a;font-size:14px;font-weight:700;"
                         "letter-spacing:1.5px;background:transparent;");
        return l;
    };

    // Stat cards
    auto *cardsRow = new QHBoxLayout(); cardsRow->setSpacing(10);
    auto mkCard=[&](const QString&lbl,QLabel*&val,const QString&col="#1e2a3a"){
        auto*c=new QWidget(content); c->setObjectName("StatCard");
        c->setMinimumWidth(110);
        auto*cv=new QVBoxLayout(c); cv->setContentsMargins(12,10,12,10); cv->setSpacing(4);
        auto*ll=new QLabel(lbl,c);
        ll->setStyleSheet("color:#8a8a8a;font-size:14px;font-weight:700;"
                          "letter-spacing:1px;background:transparent;");
        val=new QLabel("-",c);
        val->setStyleSheet(QString("color:%1;font-size:18px;font-weight:600;"
                                   "background:transparent;").arg(col));
        cv->addWidget(ll); cv->addWidget(val);
        cardsRow->addWidget(c,1);
    };
    mkCard("CONNECTIONS",m_cardConns,"#6366f1");
    mkCard("OUT RATE",   m_cardOut,  "#6366f1");
    mkCard("IN RATE",    m_cardIn,   "#10b981");
    mkCard("TOTAL DATA", m_cardTotal,"#1e2a3a");
    mkCard("ANOMALY",    m_cardAnomaly,"#10b981");
    cl->addLayout(cardsRow);

    // Bandwidth graph
    cl->addWidget(mkSec("BANDWIDTH  (last 5 minutes)"));
    m_graph = new ProcBwGraph(content);
    cl->addWidget(m_graph);

    // Active connections table
    cl->addWidget(mkSec("ACTIVE CONNECTIONS"));
    m_connTable = new QTableWidget(0,5,content);
    m_connTable->setHorizontalHeaderLabels(
        {"DOMAIN / IP","PROTO","STATE","OUT","IN"});
    m_connTable->setFixedHeight(180);
    m_connTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_connTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_connTable->setAlternatingRowColors(true);
    m_connTable->setShowGrid(false);
    m_connTable->verticalHeader()->setVisible(false);
    m_connTable->verticalHeader()->setDefaultSectionSize(40);
    m_connTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_connTable->setColumnWidth(0,240);
    m_connTable->setColumnWidth(1,60);
    m_connTable->setColumnWidth(2,110);
    m_connTable->setColumnWidth(3,90);
    m_connTable->setColumnWidth(4,90);
    cl->addWidget(m_connTable);

    // DNS table
    cl->addWidget(mkSec("DNS QUERIES"));
    m_dnsTable = new QTableWidget(0,4,content);
    m_dnsTable->setHorizontalHeaderLabels({"DOMAIN","IP","TTL","LAST SEEN"});
    m_dnsTable->setFixedHeight(150);
    m_dnsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_dnsTable->setAlternatingRowColors(true);
    m_dnsTable->setShowGrid(false);
    m_dnsTable->verticalHeader()->setVisible(false);
    m_dnsTable->verticalHeader()->setDefaultSectionSize(30);
    m_dnsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
    m_dnsTable->setColumnWidth(0,240);
    m_dnsTable->setColumnWidth(1,140);
    m_dnsTable->setColumnWidth(2,70);
    m_dnsTable->setColumnWidth(3,130);
    cl->addWidget(m_dnsTable);

    // Mini map
    cl->addWidget(mkSec("GEOGRAPHIC CONNECTIONS"));
    m_mapScene = new QGraphicsScene(0,0,MW,MH,this);
    m_mapScene->setBackgroundBrush(QBrush(QColor("#080d13")));
    m_mapView = new QGraphicsView(m_mapScene,content);
    m_mapView->setFixedHeight(int(MH));
    m_mapView->setRenderHint(QPainter::Antialiasing);
    m_mapView->setStyleSheet("border:1px solid #555555;border-radius:8px;"
                              "background:#080d13;");
    m_mapView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_mapView->setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    cl->addWidget(m_mapView);
    cl->addStretch();

    m_scroll->setWidget(content);
    cardLay->addWidget(m_scroll,1);
}

void ProcessDetailOverlay::repositionCard()
{
    if (!m_card) return;
    int w = qMin(width()-80, 960);
    int h = height() - 60;
    int x = (width()-w)/2;
    int y = 30;
    m_card->setGeometry(x,y,w,h);
}

void ProcessDetailOverlay::resizeEvent(QResizeEvent *e)
{
    QWidget::resizeEvent(e);
    repositionCard();
}

QPointF ProcessDetailOverlay::geo2scene(double lat, double lon) const {
    return {(lon+180.0)/360.0*MW,(90.0-lat)/180.0*MH};
}

void ProcessDetailOverlay::drawMiniMap(
    const QVector<TrafficEntry> &conns,
    const QMap<QString,RouteEntry> &routes)
{
    m_mapScene->clear();

    QPen grid(QColor(255,255,255,8),0.5);
    for(int lat=-60;lat<=60;lat+=30){
        auto a=geo2scene(lat,-180),b=geo2scene(lat,180);
        m_mapScene->addLine(a.x(),a.y(),b.x(),b.y(),grid)->setZValue(0);}
    for(int lon=-150;lon<=180;lon+=30){
        auto a=geo2scene(90,lon),b=geo2scene(-90,lon);
        m_mapScene->addLine(a.x(),a.y(),b.x(),b.y(),grid)->setZValue(0);}

    QColor lc(35,48,62,200); QPen lp(QColor(50,68,85,80),0.5);
    auto land=[&](QPolygonF p){m_mapScene->addPolygon(p,lp,QBrush(lc))->setZValue(1);};
    land(QPolygonF({geo2scene(70,-140),geo2scene(72,-95),geo2scene(65,-60),
        geo2scene(47,-53),geo2scene(25,-80),geo2scene(10,-77),
        geo2scene(20,-105),geo2scene(32,-117),geo2scene(49,-124),geo2scene(70,-140)}));
    land(QPolygonF({geo2scene(12,-72),geo2scene(0,-50),geo2scene(-34,-58),
        geo2scene(-55,-68),geo2scene(-18,-75),geo2scene(12,-72)}));
    land(QPolygonF({geo2scene(71,28),geo2scene(55,24),geo2scene(36,-9),
        geo2scene(51,2),geo2scene(71,28)}));
    land(QPolygonF({geo2scene(37,10),geo2scene(22,37),geo2scene(-34,26),
        geo2scene(5,-5),geo2scene(37,10)}));
    land(QPolygonF({geo2scene(72,60),geo2scene(68,140),geo2scene(35,130),
        geo2scene(8,78),geo2scene(22,68),geo2scene(55,37),geo2scene(72,60)}));
    land(QPolygonF({geo2scene(-15,129),geo2scene(-24,154),
        geo2scene(-38,147),geo2scene(-22,114),geo2scene(-15,129)}));
    land(QPolygonF({geo2scene(28,72),geo2scene(28,88),
        geo2scene(8,78),geo2scene(22,68),geo2scene(28,72)}));

    // Source dot (Bhopal)
    QPointF src = geo2scene(23.25, 77.40);
    m_mapScene->addEllipse(src.x()-10,src.y()-10,20,20,
        QPen(Qt::NoPen),QBrush(QColor(29,110,245,40)))->setZValue(4);
    m_mapScene->addEllipse(src.x()-5,src.y()-5,10,10,
        QPen(Qt::NoPen),QBrush(QColor("#6366f1")))->setZValue(5);
    auto*sl=m_mapScene->addText("you");
    sl->setDefaultTextColor(QColor("#6366f1"));
    sl->setFont(QFont("Ubuntu Mono",7));
    sl->setPos(src.x()+7,src.y()-8); sl->setZValue(6);

    // Route arcs
    static const QStringList COLS={"#6366f1","#10b981","#ce9178",
                                    "#8b5cf6","#ef4444","#6366f1"};
    int ci=0;
    QSet<QString> done;
    for (const auto &e : conns) {
        if (e.process!=m_process && e.pid!=m_pid) continue;
        if (done.contains(e.destIp)) continue;
        done.insert(e.destIp);
        if (!routes.contains(e.destIp)) continue;
        const RouteEntry &re=routes[e.destIp];
        if (!re.isReady()) continue;

        QColor col(COLS[ci++%COLS.size()]);
        QVector<QPointF> pts={src};
        for (const auto &h:re.hops) {
            if (!h.hasGeo()) continue;
            if (qAbs(h.lat)<0.1&&qAbs(h.lon)<0.1) continue;
            pts.append(geo2scene(h.lat,h.lon));
        }
        if (pts.size()<2) continue;
        for (int i=0;i+1<pts.size();++i) {
            QPointF p1=pts[i],p2=pts[i+1];
            QPointF mid=(p1+p2)/2.0;
            mid.setY(mid.y()-QLineF(p1,p2).length()*0.15);
            QPainterPath path; path.moveTo(p1); path.quadTo(mid,p2);
            auto*arc=m_mapScene->addPath(path,QPen(col,1.5));
            arc->setOpacity(0.8); arc->setZValue(3);
            m_mapScene->addEllipse(p2.x()-4,p2.y()-4,8,8,
                QPen(Qt::NoPen),QBrush(col))->setZValue(5);
        }
    }
    m_mapView->fitInView(m_mapScene->sceneRect(),Qt::KeepAspectRatio);
}

void ProcessDetailOverlay::showProcess(
    const QString &process,
    const QVector<ProcEntry> &procs,
    const QVector<TrafficEntry> &conns,
    const QVector<DnsEntry> &dns,
    const QMap<QString,RouteEntry> &routes)
{
    m_process = process;

    ProcEntry proc;
    for (const auto &p : procs)
        if (p.process==process) { proc=p; break; }
    m_pid = proc.pid;

    populateInfo(proc);
    populateConnections(conns);
    populateDns(dns);
    drawMiniMap(conns, routes);
    m_graph->addSample(proc.rateOutBps, proc.rateInBps);

    repositionCard();
    setVisible(true);
    raise();
    m_scroll->verticalScrollBar()->setValue(0);
}

void ProcessDetailOverlay::populateInfo(const ProcEntry &proc)
{
    m_procName->setText(proc.process);
    m_exePath->setText(proc.exe.isEmpty()?"unknown":proc.exe);
    m_pidLabel->setText(QString("PID %1").arg(proc.pid));

    auto fR=[](quint32 b)->QString{
        if(b==0)return"-";
        if(b<1024)return QString("%1 B/s").arg(b);
        if(b<1048576)return QString("%1 KB/s").arg(b/1024.0,0,'f',1);
        return QString("%1 MB/s").arg(b/1048576.0,0,'f',1);};
    auto fB=[](quint64 b)->QString{
        if(b<1024)return QString("%1 B").arg(b);
        if(b<1048576)return QString("%1 KB").arg(b/1024.0,0,'f',1);
        if(b<1073741824)return QString("%1 MB").arg(b/1048576.0,0,'f',1);
        return QString("%1 GB").arg(b/1073741824.0,0,'f',2);};

    m_cardConns->setText(QString::number(proc.totalConns));
    m_cardOut->setText(fR(proc.rateOutBps));
    m_cardIn->setText(fR(proc.rateInBps));
    m_cardTotal->setText(fB(proc.bytesOut+proc.bytesIn));

    bool clean = proc.anomalyStr.isEmpty() ||
                 proc.anomalyStr=="NONE" || proc.anomalyStr=="None";
    m_cardAnomaly->setText(clean ? "Clean" : proc.anomalyStr);
    m_cardAnomaly->setStyleSheet(
        QString("color:%1;font-size:18px;font-weight:600;"
                "background:transparent;")
            .arg(clean?"#10b981":"#ef4444"));
}

void ProcessDetailOverlay::populateConnections(
    const QVector<TrafficEntry> &conns)
{
    QVector<TrafficEntry> mine;
    for (const auto &e : conns) {
        bool match = (m_pid>0 && e.pid==m_pid) ||
                     e.process==m_process ||
                     e.process.startsWith(m_process) ||
                     m_process.startsWith(e.process);
        if (match) mine.append(e);
    }

    m_connTable->setRowCount(mine.size());
    auto item=[](const QString&t,const QColor&c)->QTableWidgetItem*{
        auto*it=new QTableWidgetItem(t);
        it->setForeground(QBrush(c));
        it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
        return it;};

    for (int i=0;i<mine.size();++i) {
        const TrafficEntry&e=mine[i];
        QString dom=(e.domain.isEmpty()||e.domain=="-")?e.destIp:e.domain;
        QColor sc = e.state==ConnState::Established?QColor("#10b981"):
                    e.state==ConnState::UdpActive  ?QColor("#3794ff"):
                                                     QColor("#8a8a8a");
        m_connTable->setItem(i,0,item(dom,         QColor("#6366f1")));
        m_connTable->setItem(i,1,item(e.protocol,  QColor("#8a8a8a")));
        m_connTable->setItem(i,2,item(e.stateString(),sc));
        m_connTable->setItem(i,3,item(e.formatRate(e.rateOutBps),QColor("#6366f1")));
        m_connTable->setItem(i,4,item(e.formatRate(e.rateInBps), QColor("#10b981")));
    }
}

void ProcessDetailOverlay::populateDns(const QVector<DnsEntry> &dns)
{
    QVector<DnsEntry> mine;
    for (const auto &d : dns) {
        bool match = (m_pid>0 && d.queriedByPid==m_pid) ||
                     d.queriedByComm==m_process ||
                     d.queriedByComm.startsWith(m_process) ||
                     m_process.startsWith(d.queriedByComm);
        if (match) mine.append(d);
    }

    m_dnsTable->setRowCount(mine.size());
    auto item=[](const QString&t,const QColor&c)->QTableWidgetItem*{
        auto*it=new QTableWidgetItem(t);
        it->setForeground(QBrush(c));
        it->setFlags(Qt::ItemIsEnabled|Qt::ItemIsSelectable);
        return it;};

    for (int i=0;i<mine.size();++i) {
        const DnsEntry&d=mine[i];
        QColor ttlC = d.ttlRemaining>60?QColor("#10b981"):
                      d.ttlRemaining>10?QColor("#ce9178"):QColor("#ef4444");
        QString ls=QDateTime::fromSecsSinceEpoch(d.lastSeen).toString("hh:mm:ss");
        m_dnsTable->setItem(i,0,item(d.domain,      QColor("#6366f1")));
        m_dnsTable->setItem(i,1,item(d.ip,           QColor("#cccccc")));
        m_dnsTable->setItem(i,2,item(d.ttlString(),  ttlC));
        m_dnsTable->setItem(i,3,item(ls,             QColor("#8a8a8a")));
    }
}

void ProcessDetailOverlay::hide()
{
    m_graph->clear();
    setVisible(false);
}

void ProcessDetailOverlay::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.fillRect(rect(), QColor(6,11,16,220));
}

void ProcessDetailOverlay::keyPressEvent(QKeyEvent *e)
{
    if (e->key()==Qt::Key_Escape) { hide(); emit closed(); }
    else QWidget::keyPressEvent(e);
}
