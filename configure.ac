#
# TODO: Add license preamble
#

AC_INIT([libnghq], [0.0.1], [samuelh@rd.bbc.co.uk])
AM_INIT_AUTOMAKE
AC_OUTPUT
AC_CONFIG_HEADERS([config.h])

LT_INIT()

AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_MKDIR_P

AC_CONFIG_MACRO_DIR([m4])

#AC_CONFIG_HEADERS([config.h])

# Check for required nghttp2 for HPACK
PKG_CHECK_MODULES([NGHTTP2], [libnghttp2])

# Check for required ngtcp2
PKG_CHECK_MODULES([NGTCP2], [libngtcp2])

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  include/nghq/Makefile
  tests/Makefile
  examples/Makefile
])

