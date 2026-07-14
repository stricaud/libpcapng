include_directories(AFTER ${LIBPCAPNG_INCLUDE_DIRS} ${Python_INCLUDE_DIRS})

# ── Embed all .posa protocol definitions as C strings (self-contained module) ─
file(GLOB POSA_FILES "${CMAKE_SOURCE_DIR}/bin/protos/*.posa")
set(BUILTIN_PROTOS_H "${CMAKE_CURRENT_BINARY_DIR}/builtin_protos.h")

add_custom_command(
    OUTPUT "${BUILTIN_PROTOS_H}"
    COMMAND python3 "${CMAKE_CURRENT_SOURCE_DIR}/embed_protos.py"
            "${CMAKE_SOURCE_DIR}/bin/protos"
            "${BUILTIN_PROTOS_H}"
    DEPENDS ${POSA_FILES} "${CMAKE_CURRENT_SOURCE_DIR}/embed_protos.py"
    COMMENT "Embedding .posa protocol definitions into builtin_protos.h")

# ── pycapng — pcapng file I/O + pcapsh script engine (from pycapng import pcapsh)
set(PYCAPNG_SRC
    pycapng.cpp
    pypcapsh.cpp
    pycapture.cpp
    pyposa.cpp
    ${CMAKE_SOURCE_DIR}/bin/pcapsh.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_layer.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_posa.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_io.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_eval.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_main.c
    ${CMAKE_SOURCE_DIR}/bin/linenoise/linenoise.c
)

add_library(pycapng MODULE ${PYCAPNG_SRC} "${BUILTIN_PROTOS_H}")
set_source_files_properties("${BUILTIN_PROTOS_H}" PROPERTIES HEADER_FILE_ONLY TRUE)

target_include_directories(pycapng PRIVATE
    ${CMAKE_SOURCE_DIR}/bin
    ${LIBPCAPNG_INCLUDE_DIRS}
    ${Python_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(pycapng PRIVATE pybind11::module pcapng_static)

set_target_properties(pycapng PROPERTIES PREFIX "${PYTHON_MODULE_PREFIX}"
    SUFFIX "${PYTHON_MODULE_EXTENSION}"
    COMPILE_FLAGS "-DPYBIND11_PYTHON_VERSION=${PYBIND11_PYTHON_VERSION}")

# Require C++14: std::make_unique, initialized lambda captures.
target_compile_features(pycapng PRIVATE cxx_std_14)

if(SKBUILD)
    # scikit-build-core sets SKBUILD=1; install relative to the wheel root.
    install(TARGETS pycapng LIBRARY DESTINATION . COMPONENT Python)
else()
    execute_process(
      COMMAND python3 -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
      OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(STATUS "PYTHON_SITE_PACKAGES='${PYTHON_SITE_PACKAGES}'")
    install(TARGETS pycapng LIBRARY
        DESTINATION "${PYTHON_SITE_PACKAGES}"
        COMPONENT Python)
endif()

