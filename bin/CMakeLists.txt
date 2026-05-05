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

add_test(
    NAME pcapsh_tests
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(pcapsh_tests PROPERTIES
    ENVIRONMENT "PCAPSH=$<TARGET_FILE:pcapsh>"
)
