add_library(Poly1305 poly1305.c)
target_link_libraries(Poly1305 PUBLIC qc)
target_include_directories(Poly1305 PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)


if (CC20_TESTS)
    add_subdirectory(tests)
endif()
