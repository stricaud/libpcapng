enable_testing()

add_executable(writeall writeall.c)
target_link_libraries(writeall ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(WriteAll writeall)

add_executable(read read.c)
target_link_libraries(read ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Read read)

add_executable(dns-write dns-write.c)
target_link_libraries(dns-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Dns-Write dns-write)

add_executable(tcp-sequence tcp-sequence.c)
target_link_libraries(tcp-sequence ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Tcp-Sequence tcp-sequence)

add_executable(dhcp-write dhcp-write.c)
target_link_libraries(dhcp-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Dhcp-Write dhcp-write)

add_executable(ntp-write ntp-write.c)
target_link_libraries(ntp-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Ntp-Write ntp-write)

add_executable(ssl-http2-write ssl-http2-write.c)
target_link_libraries(ssl-http2-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Ssl-Http2-Write ssl-http2-write)

add_executable(rdp-write rdp-write.c)
target_link_libraries(rdp-write ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Rdp-Write rdp-write)

add_executable(reasm reasm.c)
target_link_libraries(reasm ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Reasm reasm)

add_executable(pcapng-spec pcapng-spec.c)
target_link_libraries(pcapng-spec ${LIBPCAPNG_LIBRARY} ${CMAKE_DL_LIBS})
add_test(Pcapng-Spec pcapng-spec)
