
# Simple CMakeFile infrastructure to build the 
# Virscient client/file transfer application

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project("network" VERSION 1.0 DESCRIPTION "Virscient Technical Assessment" LANGUAGES C)

# List of compilation units:
set(COMMON_SRC 
    main.c
    client/client.c
    server/server.c
    common/common.c
    libs/rabin/rabinpoly.c
    libs/sha256/sha256.c
    libs/crc32/crc32.c
    libs/thpool/thpool.c
)

# Application name:
add_executable(network)

# Set compiler warning flags:
target_compile_options(network PRIVATE -Wall -Wextra -Werror)

# Prepare to link with Linux Threads (pthread) external library (needed by the server thread worker pool)
find_package(Threads)
target_link_libraries(network ${CMAKE_THREAD_LIBS_INIT})

# Path to include folders:
target_include_directories(network PRIVATE "client/inc")
target_include_directories(network PRIVATE "server/inc")
target_include_directories(network PRIVATE "commands/inc")
target_include_directories(network PRIVATE "common/inc")
target_include_directories(network PRIVATE "libs/rabin/inc")
target_include_directories(network PRIVATE "libs/sha256/inc")
target_include_directories(network PRIVATE "libs/crc32/inc")
target_include_directories(network PRIVATE "libs/thpool/inc")

target_sources(network PRIVATE ${COMMON_SRC})
