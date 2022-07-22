Name: libpcapng
Description: PcapNG Library
Version: ${LIBPCAPNG_VERSION}
Requires: 
Conflicts:
Libs: -L${CMAKE_INSTALL_FULL_LIBDIR} -lpcapng
Libs.private: 
Cflags: -I${CMAKE_INSTALL_PREFIX}/include
