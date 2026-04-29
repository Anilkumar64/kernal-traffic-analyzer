cmake_minimum_required(VERSION 3.22)
project(KernelTrafficAnalyzer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)

find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
find_package(SQLite3 REQUIRED)

set(SOURCES
    main.cpp
    core/ProcReader.cpp
    core/TrafficModel.cpp
    core/ProcModel.cpp
    core/DnsModel.cpp
    core/AnomalyModel.cpp
    core/RouteModel.cpp
    core/HistoryDB.cpp
    core/Exporter.cpp
    ui/MainWindow.cpp
    ui/Sidebar.cpp
    ui/TitleBar.cpp
    ui/StatusBar.cpp
    ui/StatCard.cpp
    ui/ConnectionsTab.cpp
    ui/ProcessesTab.cpp
    ui/DnsTab.cpp
    ui/AnomalyTab.cpp
    ui/RoutesTab.cpp
    ui/HistoryTab.cpp
    ui/NetworkPerfTab.cpp
    ui/delegates/ProtoBadgeDelegate.cpp
    ui/delegates/StateBadgeDelegate.cpp
    ui/delegates/RateBarDelegate.cpp
    ui/delegates/TtlBarDelegate.cpp
    ui/delegates/MonoDelegate.cpp
    ui/delegates/ColorTextDelegate.cpp
    ui/delegates/PerfBarDelegate.cpp
)

add_executable(kernel_traffic_analyzer ${SOURCES})
target_link_libraries(kernel_traffic_analyzer PRIVATE
    Qt6::Core Qt6::Gui Qt6::Widgets SQLite::SQLite3)
target_include_directories(kernel_traffic_analyzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR})
