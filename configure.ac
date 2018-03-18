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

LIBEV_CFLAGS=
LIBEV_LIBS=
HAVE_LIBEV=0
AX_LIB_EV([>= 4.0], [
	   LIBEV_CFLAGS=$libev_CFLAGS
	   LIBEV_LIBS=$libev_LIBS
	   HAVE_LIBEV=1
	   ], [
	   AC_MSG_WARN([[libev development headers and library are required to build examples, please
install the relevant packages for your system to enable the examples to be
built.]])
	   ])
AM_CONDITIONAL([HAVE_LIBEV], [test "$HAVE_LIBEV" -eq 1])
AC_DEFINE_UNQUOTED([HAVE_LIBEV], [$HAVE_LIBEV], [If we have libev available])
AC_SUBST([LIBEV_CFLAGS])
AC_SUBST([LIBEV_LIBS])

AC_CONFIG_FILES([
  Makefile
  lib/Makefile
  include/nghq/Makefile
  tests/Makefile
  examples/Makefile
])

AC_OUTPUT
