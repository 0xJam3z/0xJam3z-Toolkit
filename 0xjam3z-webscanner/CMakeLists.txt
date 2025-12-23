cmake_minimum_required(VERSION 3.16)
project(0xjam3z-scanner LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(0xjam3z-scanner
    main.cpp
)

target_include_directories(0xjam3z-scanner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)
