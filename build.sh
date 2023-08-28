#!/bin/bash

mkdir -p ./build
cd ./build
rm -fr *
cmake ..
cd ../
cmake --build ./build


