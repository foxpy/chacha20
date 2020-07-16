cmake_minimum_required(VERSION 3.1)
project(ChaCha20)

if (MSVC)
	message(FATAL_ERROR "MSVC is not supported, use mingw-gcc or clang")
endif()

add_executable(cc20 cc20.c args.c util.c chacha20.c)
set_property(TARGET cc20 PROPERTY C_STANDARD 11)
target_compile_options(cc20 PUBLIC -Wall -Wextra -Wpedantic)

add_executable(chacha20-test test.c chacha20.c util.c)
set_property(TARGET chacha20-test PROPERTY C_STANDARD 11)
target_compile_options(chacha20-test PUBLIC -Wall -Wextra -Wpedantic)

enable_testing()
add_test(NAME ChaCha20Runs COMMAND chacha20-test)
