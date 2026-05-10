add_executable(pcapsh
    pcapsh.c
    pcapsh_layer.c
    pcapsh_posa.c
    pcapsh_io.c
    pcapsh_eval.c
    pcapsh_main.c
    linenoise/linenoise.c
)

target_include_directories(pcapsh PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${LIBPCAPNG_INCLUDE_DIRS}
)

target_link_libraries(pcapsh pcapng_static)

# Bake in the installed protos path and the source protos path (for in-tree builds).
target_compile_definitions(pcapsh PRIVATE
    PCAPSH_PROTOS_INSTALL_DIR="${CMAKE_INSTALL_FULL_DATAROOTDIR}/pcapsh/protos"
    PCAPSH_PROTOS_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}/protos"
)

install(TARGETS pcapsh DESTINATION bin)

# Install shared protocol definitions to share/pcapsh/protos/
install(DIRECTORY protos/
    DESTINATION share/pcapsh/protos
    FILES_MATCHING PATTERN "*.posa"
)

add_test(
    NAME pcapsh_tests
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/run_tests.sh
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
)
set_tests_properties(pcapsh_tests PROPERTIES
    ENVIRONMENT "PCAPSH=$<TARGET_FILE:pcapsh>"
)
