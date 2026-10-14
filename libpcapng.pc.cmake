prefix=@CMAKE_INSTALL_PREFIX@
exec_prefix=${prefix}
libdir=@CMAKE_INSTALL_FULL_LIBDIR@
includedir=@CMAKE_INSTALL_FULL_INCLUDEDIR@

Name: libpcapng
Description: PcapNG Library
Version: @LIBPCAPNG_VERSION@
Requires:
Conflicts:
Libs: -L${libdir} -lpcapng
Libs.private:
Cflags: -I${includedir}
