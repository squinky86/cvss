cmake_minimum_required(VERSION 3.2)

project(libcvss)

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(src)
target_include_directories(cvss PUBLIC include)
