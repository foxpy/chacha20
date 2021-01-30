cmake_minimum_required(VERSION 3.1)
project(ChaCha20)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
add_compile_options(-Wall -Wextra -Wpedantic)

option(CC20_TESTS OFF "Build tests")
if(CC20_TESTS)
    enable_testing()
endif()

add_subdirectory(qc)
add_subdirectory(src)
