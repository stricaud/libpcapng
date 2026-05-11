include_directories(AFTER ${LIBPCAPNG_INCLUDE_DIRS} ${Python_INCLUDE_DIRS})

execute_process(
  COMMAND python3 -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
  OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "PYTHON_SITE_PACKAGES='${PYTHON_SITE_PACKAGES}'")

# ── pycapng — existing pcapng file I/O binding ───────────────────────────────
set(PYCAPNG_SRC
  pycapng.cpp
  )

add_library(pycapng MODULE ${PYCAPNG_SRC})

target_link_libraries(pycapng PRIVATE pybind11::module pcapng_static)

set_target_properties(pycapng PROPERTIES PREFIX "${PYTHON_MODULE_PREFIX}"
  SUFFIX "${PYTHON_MODULE_EXTENSION}"
  COMPILE_FLAGS "-DPYBIND11_PYTHON_VERSION=${PYBIND11_PYTHON_VERSION}")

install(TARGETS pycapng LIBRARY
  DESTINATION "${PYTHON_SITE_PACKAGES}"
  COMPONENT Python)

# ── pcapsh — script engine binding (from libpcapng import pcapsh) ─────────────
set(PYPCAPSH_SRC
    pypcapsh.cpp
    ${CMAKE_SOURCE_DIR}/bin/pcapsh.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_layer.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_posa.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_io.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_eval.c
    ${CMAKE_SOURCE_DIR}/bin/pcapsh_main.c
    ${CMAKE_SOURCE_DIR}/bin/linenoise/linenoise.c
)

add_library(pcapsh_pymod MODULE ${PYPCAPSH_SRC})

set_target_properties(pcapsh_pymod PROPERTIES
    OUTPUT_NAME "pcapsh"
    PREFIX "${PYTHON_MODULE_PREFIX}"
    SUFFIX "${PYTHON_MODULE_EXTENSION}"
    COMPILE_FLAGS "-DPYBIND11_PYTHON_VERSION=${PYBIND11_PYTHON_VERSION}")

target_include_directories(pcapsh_pymod PRIVATE
    ${CMAKE_SOURCE_DIR}/bin
    ${LIBPCAPNG_INCLUDE_DIRS}
    ${Python_INCLUDE_DIRS})

target_link_libraries(pcapsh_pymod PRIVATE pybind11::module pcapng_static)

target_compile_definitions(pcapsh_pymod PRIVATE
    PCAPSH_PROTOS_INSTALL_DIR="${CMAKE_INSTALL_FULL_DATAROOTDIR}/pcapsh/protos"
    PCAPSH_PROTOS_SRC_DIR="${CMAKE_SOURCE_DIR}/bin/protos")

set(LIBPCAPNG_PYPACKAGE_DIR "${PYTHON_SITE_PACKAGES}/libpcapng")
install(TARGETS pcapsh_pymod LIBRARY DESTINATION "${LIBPCAPNG_PYPACKAGE_DIR}" COMPONENT Python)
install(FILES libpcapng/__init__.py DESTINATION "${LIBPCAPNG_PYPACKAGE_DIR}" COMPONENT Python)

# Keep the in-tree libpcapng/ package dir up-to-date after every build
add_custom_command(TARGET pcapsh_pymod POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy
        "$<TARGET_FILE:pcapsh_pymod>"
        "${CMAKE_SOURCE_DIR}/bindings/python/libpcapng/$<TARGET_FILE_NAME:pcapsh_pymod>"
    COMMENT "Copying pcapsh module into source libpcapng/ package")

