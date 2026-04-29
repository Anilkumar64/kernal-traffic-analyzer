cmake_minimum_required(VERSION 3.22)

add_executable(kta_packet_backend
    src/main.cpp
    src/PacketBackend.cpp
)

target_compile_features(kta_packet_backend PRIVATE cxx_std_17)
target_include_directories(kta_packet_backend PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(kta_packet_backend PRIVATE pthread)

