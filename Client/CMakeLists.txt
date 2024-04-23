cmake_minimum_required(VERSION 3.5)
project (host)

set(SOURCES
client.cpp
main_test.cpp
)

find_package (OpenCV REQUIRED)
add_executable(host ${SOURCES})
# include_directories ("/usr/include/opencv4/")
include_directories( ${OpenCV_INCLUDE_DIRS} )
target_link_libraries( host ${OpenCV_LIBS} )