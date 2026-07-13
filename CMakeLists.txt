cmake_minimum_required (VERSION 3.20)
project (libpcapng)

if(POLICY CMP0148)
  cmake_policy(SET CMP0148 NEW)
endif()

if(${CMAKE_CURRENT_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_BINARY_DIR})
message(FATAL_ERROR "CMake generation is not allowed within the source directory!
Remove the CMakeCache.txt file and try again from another folder, e.g.:

   rm CMakeCache.txt
   mkdir build
   cd build
   cmake ..
")
endif()

# add_definitions(-DDEBUG=1)
include(GNUInstallDirs)
enable_testing()

include(FindPkgConfig)
include(FindPackageHandleStandardArgs)

file(STRINGS VERSION VERSION)
set(LIBPCAPNG_VERSION ${VERSION})
file(STRINGS "VERSION" LIBPCAPNG_VERSION)
string(REGEX MATCH "^[0-9]+" LIBPCAPNG_VERSION_MAJOR ${LIBPCAPNG_VERSION})
string(REGEX MATCH "[0-9]+$" LIBPCAPNG_VERSION_MINOR ${LIBPCAPNG_VERSION})
message("Libpcapng Version: ${LIBPCAPNG_VERSION}")
message("Libpcapng Version Major: ${LIBPCAPNG_VERSION_MAJOR}")
message("Libpcapng Version Minor: ${LIBPCAPNG_VERSION_MINOR}")

configure_file("${libpcapng_SOURCE_DIR}/libpcapng.pc.cmake" "${libpcapng_BINARY_DIR}/libpcapng.pc")
install(FILES "${libpcapng_BINARY_DIR}/libpcapng.pc" DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig" COMPONENT Headers)

include_directories(AFTER ${libpcapng_SOURCE_DIR}/lib/include)

option(LIBPCAPNG_BINDINGS "Build the Python (pybind11) bindings" ON)
if(LIBPCAPNG_BINDINGS)
  find_package(Python REQUIRED COMPONENTS Interpreter Development.Module)
  set(PYBIND11_FINDPYTHON ON)
  find_package(pybind11 CONFIG REQUIRED)
endif()

# <pybind11>
# execute_process (
#    COMMAND pybind11-config --cmakedir
#    OUTPUT_VARIABLE PYBIND11_CMAKEDIR
#    OUTPUT_STRIP_TRAILING_WHITESPACE
# )
# set(pybind11_ROOT "${PYBIND11_CMAKEDIR}")
# set(PYBIND11_FINDPYTHON "off")
# find_package(pybind11 CONFIG REQUIRED)
# message("Using Python libraries: ${Python_LIBRARIES}")
# </pybind11>

# find_path(WANDIO_INCLUDE_DIR NAMES wandio.h)
# find_library(WANDIO_LIBRARY NAMES wandio REQUIRED)
# find_package_handle_standard_args(wandio "Could not find wandio library header and/or library ${DEFAULT_MSG}" WANDIO_INCLUDE_DIR WANDIO_LIBRARY)
# if(WANDIO_FOUND)
#   message("-- Found wandio: ${WANDIO_INCLUDE_DIR}" )
# endif()

set(LIBPCAPNG_INCLUDE_DIRS "${libpcapng_SOURCE_DIR}/lib/include/")
# Link by target name: a raw path would give make no pcapng -> consumer edge,
# so parallel builds can start lib/tests before the library exists.
set(LIBPCAPNG_LIBRARY pcapng)
if (APPLE)
  set(CMAKE_MACOSX_RPATH ON)
endif()

add_definitions(-g)

add_subdirectory(lib)
add_subdirectory(bin)
if(LIBPCAPNG_BINDINGS)
  add_subdirectory(bindings)
endif()

