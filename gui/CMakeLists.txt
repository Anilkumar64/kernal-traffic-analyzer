cmake_minimum_required(VERSION 3.22)
project(KernelTrafficAnalyzer VERSION 1.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets)
set(SOURCES
    main.cpp
    core/ProcReader.cpp
    core/TrafficModel.cpp
    core/ProcModel.cpp
    ui/MainWindow.cpp
    ui/Sidebar.cpp
    ui/ConnectionsTab.cpp
    ui/ProcessesTab.cpp
    ui/RouteMapWidget.cpp
    ui/DnsTab.cpp
    ui/AnomalyTab.cpp
)
add_executable(kernel_traffic_analyzer ${SOURCES})
target_link_libraries(kernel_traffic_analyzer PRIVATE Qt6::Core Qt6::Gui Qt6::Widgets)
target_include_directories(kernel_traffic_analyzer PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
