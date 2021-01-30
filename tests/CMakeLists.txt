function(cc20_add_test target)
    add_executable(${target} ${target}.c)
    target_link_libraries(${target} PUBLIC qc ChaCha20)
    add_test(NAME ${target} COMMAND ${target})
endfunction()

cc20_add_test(chacha20-gen-key-test)
cc20_add_test(chacha20-gen-nonce-test)
