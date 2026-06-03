enable_testing()

# On macOS, DYLD_LIBRARY_PATH in the shell can shadow the build-directory library.
# Prepend the build lib path for every ctest invocation so tests always use
# the freshly built libpcapng, not a stale installed version.
if(APPLE)
  set(LIBPCAPNG_TEST_ENV "DYLD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib:$ENV{DYLD_LIBRARY_PATH}")
else()
  set(LIBPCAPNG_TEST_ENV "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/lib:$ENV{LD_LIBRARY_PATH}")
endif()

add_executable(writeall writeall.c)
target_link_libraries(writeall ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(WriteAll writeall)
set_tests_properties(WriteAll PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(read read.c)
target_link_libraries(read ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Read read)
set_tests_properties(Read PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(dns-write dns-write.c)
target_link_libraries(dns-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Dns-Write dns-write)
set_tests_properties(Dns-Write PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(tcp-sequence tcp-sequence.c)
target_link_libraries(tcp-sequence ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Tcp-Sequence tcp-sequence)
set_tests_properties(Tcp-Sequence PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(dhcp-write dhcp-write.c)
target_link_libraries(dhcp-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Dhcp-Write dhcp-write)
set_tests_properties(Dhcp-Write PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(ntp-write ntp-write.c)
target_link_libraries(ntp-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Ntp-Write ntp-write)
set_tests_properties(Ntp-Write PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(ssl-http2-write ssl-http2-write.c)
target_link_libraries(ssl-http2-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Ssl-Http2-Write ssl-http2-write)
set_tests_properties(Ssl-Http2-Write PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(rdp-write rdp-write.c)
target_link_libraries(rdp-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Rdp-Write rdp-write)
set_tests_properties(Rdp-Write PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(reasm reasm.c)
target_link_libraries(reasm ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Reasm reasm)
set_tests_properties(Reasm PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(pcapng-spec pcapng-spec.c)
target_link_libraries(pcapng-spec ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Pcapng-Spec pcapng-spec)
set_tests_properties(Pcapng-Spec PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")
