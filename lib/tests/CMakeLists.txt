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

add_executable(filter filter.c)
target_link_libraries(filter ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Filter filter)

add_executable(posa posa.c)
target_link_libraries(posa ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Posa posa)
set_tests_properties(Filter PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(surgery-roundtrip surgery-roundtrip.c)
target_link_libraries(surgery-roundtrip ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Surgery-Roundtrip surgery-roundtrip)
set_tests_properties(Surgery-Roundtrip PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(tls-keylog tls-keylog.c)
target_link_libraries(tls-keylog ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(TLS-Keylog tls-keylog)
set_tests_properties(TLS-Keylog PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

add_executable(flow-hash flow-hash.c)
target_link_libraries(flow-hash ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Flow-Hash flow-hash)
set_tests_properties(Flow-Hash PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")

# Concurrency — holds the library to the contract in threading.h. Needs threads,
# which the library itself does not, so it is skipped where they are unavailable
# (Windows has no pthreads and no capture backend either).
find_package(Threads)
if(Threads_FOUND AND NOT WIN32)
    add_executable(concurrency concurrency.c)
    target_link_libraries(concurrency ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS} Threads::Threads)
    add_test(Concurrency concurrency)
    set_tests_properties(Concurrency PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")
endif()

# Resolve the modbus_tcp.posa path: prefer the submodule, fall back to installed protos.
if(EXISTS "${CMAKE_SOURCE_DIR}/bin/protos/modbus_tcp.posa")
    set(MODBUS_POSA_PATH "${CMAKE_SOURCE_DIR}/bin/protos/modbus_tcp.posa")
elseif(DEFINED PCAPSH_PROTOS_INSTALL_DIR AND EXISTS "${PCAPSH_PROTOS_INSTALL_DIR}/modbus_tcp.posa")
    set(MODBUS_POSA_PATH "${PCAPSH_PROTOS_INSTALL_DIR}/modbus_tcp.posa")
else()
    set(MODBUS_POSA_PATH "")
endif()

add_executable(modbus-posa modbus-posa.c)
target_link_libraries(modbus-posa ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
if(MODBUS_POSA_PATH)
    target_compile_definitions(modbus-posa PRIVATE
        MODBUS_POSA_PATH="${MODBUS_POSA_PATH}")
endif()
add_test(Modbus-Posa modbus-posa)
set_tests_properties(Modbus-Posa PROPERTIES ENVIRONMENT "${LIBPCAPNG_TEST_ENV}")
