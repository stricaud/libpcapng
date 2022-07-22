include_directories(AFTER ${LIBPCAPNG_INCLUDE_DIRS})

message("include dirs: ${LIBPCAPNG_INCLUDE_DIRS}")

add_library(libpcapng SHARED
  blocks.c
  io.c
  )

add_library(libpcapng_static STATIC
  blocks.c
  io.c
  )

add_subdirectory(tests)

