cmake_minimum_required(VERSION 3.1)
project(ChaCha20)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)
add_compile_options(-Wall -Wextra -Wpedantic)
add_subdirectory(qc)

add_executable(cc20 cc20.c args.c util.c chacha20.c)
target_link_libraries(cc20 PUBLIC qc)
add_executable(chacha20-test test.c chacha20.c util.c)
target_link_libraries(chacha20-test PUBLIC qc)

enable_testing()
add_test(NAME ChaCha20Runs COMMAND chacha20-test)
