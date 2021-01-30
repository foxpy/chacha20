add_executable(chacha20-test chacha20_test.c)
target_link_libraries(chacha20-test PUBLIC ChaCha20)
add_test(NAME chacha20-test COMMAND chacha20-test)
