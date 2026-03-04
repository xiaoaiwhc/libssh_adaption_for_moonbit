cmake_minimum_required(VERSION 3.20)
project(ssh_client VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(libssh2 CONFIG REQUIRED)

add_executable(ssh_client main.cpp)

# Treat source files as UTF-8 (avoids C4819 on Chinese/GBK locale Windows)
if(MSVC)
    target_compile_options(ssh_client PRIVATE /utf-8)
endif()

target_link_libraries(ssh_client
    PRIVATE
        libssh2::libssh2
        ws2_32          # Winsock (required on Windows)
)
