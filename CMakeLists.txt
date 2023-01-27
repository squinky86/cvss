cmake_minimum_required(VERSION 3.13)
project(cvss VERSION 0.1.0)

add_library(cvss SHARED)
target_include_directories(cvss PRIVATE "${PROJECT_SOURCE_DIR}")
add_subdirectory("src")

add_executable(app)
target_sources(app PRIVATE "src/main.cpp")
target_link_libraries(app PRIVATE cvss)

install(TARGETS cvss FILE_SET HEADERS)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

target_compile_features(cvss PRIVATE cxx_std_17)
target_compile_features(app PRIVATE cxx_std_17)

set_target_properties(app PROPERTIES OUTPUT_NAME cvss)
