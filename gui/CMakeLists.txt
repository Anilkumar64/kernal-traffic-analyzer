cmake_minimum_required(VERSION 3.20)
project(KtaGui CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.2 REQUIRED COMPONENTS Core Widgets Sql Charts Network)
find_package(SQLite3 REQUIRED)

set(SOURCES
  src/main.cpp src/MainWindow.cpp src/ProcReader.cpp
  src/HistoryDB.cpp src/Exporter.cpp
  src/models/TrafficModel.cpp src/models/ProcModel.cpp
  src/models/DnsModel.cpp src/models/AnomalyModel.cpp
  src/models/RouteModel.cpp
  src/delegates/StateBadgeDelegate.cpp src/delegates/ProtoBadgeDelegate.cpp
  src/delegates/RateBarDelegate.cpp src/delegates/PerfBarDelegate.cpp
  src/delegates/TtlBarDelegate.cpp
  src/tabs/ConnectionsTab.cpp src/tabs/ProcessesTab.cpp
  src/tabs/DnsTab.cpp src/tabs/AnomalyTab.cpp
  src/tabs/RoutesTab.cpp src/tabs/HistoryTab.cpp
  src/tabs/NetworkPerfTab.cpp
)

set(HEADERS
  include/Style.h include/ProcReader.h include/HistoryDB.h
  include/Exporter.h include/MainWindow.h
  include/models/TrafficModel.h include/models/ProcModel.h
  include/models/DnsModel.h include/models/AnomalyModel.h
  include/models/RouteModel.h
  include/delegates/StateBadgeDelegate.h include/delegates/ProtoBadgeDelegate.h
  include/delegates/RateBarDelegate.h include/delegates/PerfBarDelegate.h
  include/delegates/TtlBarDelegate.h
  include/tabs/ConnectionsTab.h include/tabs/ProcessesTab.h
  include/tabs/DnsTab.h include/tabs/AnomalyTab.h
  include/tabs/RoutesTab.h include/tabs/HistoryTab.h
  include/tabs/NetworkPerfTab.h
)

add_executable(kta_gui ${SOURCES} ${HEADERS} resources/resources.qrc)
target_include_directories(kta_gui PRIVATE include)
target_compile_options(kta_gui PRIVATE -Wall -Wextra -Wpedantic -O2)
target_link_libraries(kta_gui PRIVATE
  Qt6::Core Qt6::Widgets Qt6::Sql Qt6::Charts Qt6::Network SQLite::SQLite3)
