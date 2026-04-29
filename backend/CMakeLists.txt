cmake_minimum_required(VERSION 3.20)
project(KtaBackend CXX)
set(CMAKE_CXX_STANDARD 20)
add_executable(kta_backend src/main.cpp src/PacketBackend.cpp
               src/FlowTracker.cpp src/DpiEngine.cpp src/JsonExporter.cpp)
target_include_directories(kta_backend PRIVATE include)
target_compile_options(kta_backend PRIVATE -Wall -Wextra -Wpedantic -O2)
target_link_libraries(kta_backend PRIVATE pthread)
