add_subdirectory(qc)

file(GLOB LIBZAHL_SOURCES libzahl/src/*.c)
add_library(Libzahl ${LIBZAHL_SOURCES})
target_include_directories(Libzahl PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/libzahl>)
target_compile_options(Libzahl PUBLIC -Wno-implicit-fallthrough)
