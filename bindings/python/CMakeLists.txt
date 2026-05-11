include_directories(AFTER ${LIBPCAPNG_INCLUDE_DIRS} ${Python_INCLUDE_DIRS})

execute_process(
  COMMAND python3 -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
  OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "PYTHON_SITE_PACKAGES='${PYTHON_SITE_PACKAGES}'")

# ── pycapng — pcapng file I/O + pcapsh script engine (from pycapng import pcapsh)
set(PYCAPNG_SRC
    pycapng.cpp
    pypcapsh.cpp
    ${CMAKE_SOURCE_DIR}/bin/pcapsh.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_layer.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_posa.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_io.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_eval.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_main.c
    ${CMAKE_SOURCE_DIR}/bin/linenoise/linenoise.c
)

add_library(pycapng MODULE ${PYCAPNG_SRC})

target_include_directories(pycapng PRIVATE
    ${CMAKE_SOURCE_DIR}/bin
    ${LIBPCAPNG_INCLUDE_DIRS}
    ${Python_INCLUDE_DIRS})

target_link_libraries(pycapng PRIVATE pybind11::module pcapng_static)

set_target_properties(pycapng PROPERTIES PREFIX "${PYTHON_MODULE_PREFIX}"
    SUFFIX "${PYTHON_MODULE_EXTENSION}"
    COMPILE_FLAGS "-DPYBIND11_PYTHON_VERSION=${PYBIND11_PYTHON_VERSION}")

target_compile_definitions(pycapng PRIVATE
    PCAPSH_PROTOS_INSTALL_DIR="${CMAKE_INSTALL_FULL_DATAROOTDIR}/pcapsh/protos"
    PCAPSH_PROTOS_SRC_DIR="${CMAKE_SOURCE_DIR}/bin/protos")

install(TARGETS pycapng LIBRARY
    DESTINATION "${PYTHON_SITE_PACKAGES}"
    COMPONENT Python)

