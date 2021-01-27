add_library(ChaCha20
    chacha20_new.c
    chacha20_free.c
    chacha20_random_bytes.c
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

add_executable(chacha20-test chacha20_test.c)
target_link_libraries(chacha20-test PUBLIC ChaCha20)
add_test(NAME chacha20-test COMMAND chacha20-test)
