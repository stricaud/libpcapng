add_executable(pcapsh
    pcapsh.c
    linenoise/linenoise.c
)

target_include_directories(pcapsh PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBPCAPNG_INCLUDE_DIRS}
)

target_link_libraries(pcapsh pcapng_static)

install(TARGETS pcapsh DESTINATION bin)
