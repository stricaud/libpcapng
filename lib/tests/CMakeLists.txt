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
