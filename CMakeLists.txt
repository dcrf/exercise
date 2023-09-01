
# Simple CMakeFile infrastructure to build the 
# Virscient client/file transfer application

cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

project("network" VERSION 1.0 DESCRIPTION "Virscient Technical Assessment" LANGUAGES C)

# List of compilation units:
set(COMMON_SRC 
    main.c
    client/client.c
    server/server.c
    libs/common/common.c
    libs/rabin/rabinpoly.c
    libs/sha256/sha256.c
    libs/crc32/crc32.c
)

# Application name:
add_executable(network)

# Set compiler warning flags:
target_compile_options(network PRIVATE -Wall -Wextra -Werror)

# Path to include folders:
target_include_directories(network PRIVATE "client/inc")
target_include_directories(network PRIVATE "server/inc")
target_include_directories(network PRIVATE "commands/inc")
target_include_directories(network PRIVATE "libs/common/inc")
target_include_directories(network PRIVATE "libs/rabin/inc")
target_include_directories(network PRIVATE "libs/sha256/inc")
target_include_directories(network PRIVATE "libs/crc32/inc")

target_sources(network PRIVATE ${COMMON_SRC})
