#!/bin/bash

mkdir -p ./build
rm -fr ./build/*

# For debug purposes generate an image with debug symbols
cmake -S . -B build/ -D CMAKE_BUILD_TYPE=Debug
cmake --build build/

cp build/network files/network