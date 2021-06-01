add_executable(cc20 cc20.c)
target_link_libraries(cc20 PUBLIC ChaCha20 Poly1305)
