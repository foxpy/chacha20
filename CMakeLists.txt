cmake_minimum_required(VERSION 3.1)
project(ChaCha20)

if (MSVC)
	message(FATAL_ERROR "MSVC is not supported, use mingw-gcc or clang")
endif()

add_executable(practice practice/chacha20.c)
set_property(TARGET practice PROPERTY C_STANDARD 11)
target_compile_options(practice PUBLIC -Wall -Wextra -Wpedantic)
