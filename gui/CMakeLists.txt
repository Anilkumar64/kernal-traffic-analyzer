cmake_minimum_required(VERSION 3.20)
project(KtaGui CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

find_package(Qt6 6.4 REQUIRED COMPONENTS Core Widgets Sql Charts Network)
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

add_executable(kta_gui ${SOURCES} resources/resources.qrc)
target_include_directories(kta_gui PRIVATE include)
target_compile_options(kta_gui PRIVATE -Wall -Wextra -Wpedantic -O2)
target_link_libraries(kta_gui PRIVATE
  Qt6::Core Qt6::Widgets Qt6::Sql Qt6::Charts Qt6::Network SQLite::SQLite3)
