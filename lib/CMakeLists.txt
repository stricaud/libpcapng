include_directories(AFTER ${LIBPCAPNG_INCLUDE_DIRS})

message("include dirs: ${LIBPCAPNG_INCLUDE_DIRS}")

set(LIBPCAPNG_HEADERS
  include/libpcapng/blocks.h
  include/libpcapng/easyapi.h
  include/libpcapng/io.h
  include/libpcapng/libpcapng.h
  include/libpcapng/linktypes.h
  )

set(LIBPCAPNG_SOURCES
  blocks.c
  easyapi.c
  io.c
  )

add_library(pcapng SHARED ${LIBPCAPNG_SOURCES})
set_target_properties(pcapng PROPERTIES SOVERSION 1)

add_library(pcapng_static STATIC ${LIBPCAPNG_SOURCES})
set_target_properties(pcapng_static PROPERTIES SOVERSION 1)

install(TARGETS pcapng LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR} COMPONENT Libraries)
install(TARGETS pcapng_static LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR} COMPONENT Libraries)
install(FILES ${LIBPCAPNG_HEADERS} DESTINATION include/libpcapng COMPONENT Headers)

add_subdirectory(tests)

