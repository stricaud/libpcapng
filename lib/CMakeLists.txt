include_directories(AFTER ${LIBPCAPNG_INCLUDE_DIRS})

message("include dirs: ${LIBPCAPNG_INCLUDE_DIRS}")

set(LIBPCAPNG_HEADERS
  include/libpcapng/protocols/asn1.h
  include/libpcapng/protocols/rdp.h
  include/libpcapng/blocks.h
  include/libpcapng/easyapi.h
  include/libpcapng/io.h
  include/libpcapng/libpcapng.h
  include/libpcapng/linktypes.h
  include/libpcapng/protocols/ethernet.h
  include/libpcapng/protocols/ipv4.h
  include/libpcapng/protocols/tcp.h
  include/libpcapng/protocols/udp.h
  include/libpcapng/protocols/dns.h
  include/libpcapng/protocols/icmp.h
  include/libpcapng/protocols/flow.h
  include/libpcapng/protocols/bootp.h
  include/libpcapng/protocols/dhcp.h
  include/libpcapng/protocols/ntp.h
  include/libpcapng/protocols/ssl.h
  include/libpcapng/protocols/ssh.h
  include/libpcapng/protocols/http2.h
  include/libpcapng/protocols/http2_hpack.h
  include/libpcapng/protocols/http2_stream.h
  include/libpcapng/protocols/tls_stream.h
  include/libpcapng/protocols/tcp_mss.h
  include/libpcapng/reassembly.h
  include/libpcapng/reassembly_tcp.h
  include/libpcapng/capture.h
  include/libpcapng/dissect.h
  include/libpcapng/dfilter.h
  include/libpcapng/objects.h
  include/libpcapng/posa.h
)

set(LIBPCAPNG_SOURCES
  blocks.c
  easyapi.c
  io.c
  protocols/asn1.c
  protocols/rdp.c
  protocols/ethernet.c
  protocols/ipv4.c
  protocols/tcp.c
  protocols/udp.c
  protocols/dns.c
  protocols/icmp.c
  protocols/flow.c
  protocols/dhcp.c
  protocols/ntp.c
  protocols/ssl.c
  protocols/ssh.c
  protocols/http2.c
  protocols/http2_hpack.c
  protocols/http2_stream.c
  protocols/tls_stream.c
  protocols/tcp_mss.c
  reassembly.c
  reassembly_tcp.c
  capture.c
  dissect.c
  dfilter.c
  objects.c
  posa.c
  wire_layout.c
 )

add_library(pcapng SHARED ${LIBPCAPNG_SOURCES})
set_target_properties(pcapng PROPERTIES SOVERSION 1)
set_target_properties(pcapng PROPERTIES
    BUILD_WITH_INSTALL_RPATH ON
    INSTALL_NAME_DIR "@rpath"
)
set(CMAKE_BUILD_RPATH "${CMAKE_BINARY_DIR}/lib")
set(CMAKE_INSTALL_RPATH "@rpath")

add_library(pcapng_static STATIC ${LIBPCAPNG_SOURCES})
set_target_properties(pcapng_static PROPERTIES SOVERSION 1 POSITION_INDEPENDENT_CODE ON)

if(WIN32)
  # ntohs/inet_ntop & friends live in ws2_32 (see win_compat.h). Exporting all
  # symbols spares us __declspec(dllexport) annotations on the whole public API.
  target_link_libraries(pcapng PRIVATE ws2_32)
  target_link_libraries(pcapng_static PRIVATE ws2_32)
  set_target_properties(pcapng PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

install(TARGETS pcapng LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR} COMPONENT Libraries)
install(TARGETS pcapng_static LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR} COMPONENT Libraries)
# Install the header tree preserving the protocols/ subdirectory, so consumers
# that include the umbrella <libpcapng/libpcapng.h> (which pulls protocols/*.h)
# build against an installed copy.
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/libpcapng
        DESTINATION include COMPONENT Headers FILES_MATCHING PATTERN "*.h")

if(NOT WIN32)
  add_subdirectory(tests)
endif()

