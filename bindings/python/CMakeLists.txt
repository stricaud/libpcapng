include_directories(AFTER ${LIBPCAPNG_INCLUDE_DIRS} ${Python_INCLUDE_DIRS})

set(PYCAPNG_SRC
  pycapng.cpp
  )

add_library(pycapng MODULE ${PYCAPNG_SRC})

target_link_libraries(pycapng PRIVATE pybind11::module PUBLIC ${LIBPCAPNG_LIBRARY})

set_target_properties(pycapng PROPERTIES PREFIX "${PYTHON_MODULE_PREFIX}"
  SUFFIX "${PYTHON_MODULE_EXTENSION}"
  COMPILE_FLAGS "-DPYBIND11_PYTHON_VERSION=${PYBIND11_PYTHON_VERSION}")

execute_process(
  COMMAND python3 -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
  OUTPUT_VARIABLE PYTHON_SITE_PACKAGES
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
message(STATUS "PYTHON_SITE_PACKAGES='${PYTHON_SITE_PACKAGES}'")

install(TARGETS pycapng LIBRARY
  DESTINATION "${PYTHON_SITE_PACKAGES}"
  COMPONENT Python)

