cmake_minimum_required(VERSION 3.5)
project (host)

# Create a sources variable with a link to all cpp files to compile
set(SOURCES
    client.cpp
    main_test.cpp
)

add_executable(host ${SOURCES})

find_package (OpenCV 4.0.0 REQUIRED)
include_directories ("/usr/include/opencv4/")