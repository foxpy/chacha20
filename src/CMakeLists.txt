add_library(ChaCha20
        chacha20_new.c
        chacha20_free.c
        chacha20_gen_key.c
        chacha20_gen_nonce.c
        chacha20_quarter_round.c
        chacha20_next.c
        chacha20_encrypt_bytes.c
        chacha20_decrypt_files.c
        chacha20_process_bytes.c
        )
target_link_libraries(ChaCha20 PUBLIC qc)
target_include_directories(ChaCha20 PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>)

if (CC20_TESTS)
    add_subdirectory(tests)
endif ()
