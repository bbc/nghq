#
# TODO: Add license preamble
#

AC_INIT([libnghq], [0.0.1], [samuelh@rd.bbc.co.uk])
AM_INIT_AUTOMAKE
AC_OUTPUT
AC_CONFIG_HEADERS([config.h])

LT_INIT()

# Updating library version instructions
# 1. If the library source has changed at all since the last release increment
#    LT_REVISION.
# 2. If any interfaces have been added removed or changed since the last release
#    increment LT_CURRENT and set LT_REVISION to 0.
# 3. If any interfaces have been added since the last release, increment
#    LT_AGE.
# 4. If any interfaces have been removed or changed since the last release,
#    then set LT_AGE to 0.
LT_CURRENT=0
LT_REVISION=0
LT_AGE=0
AC_SUBST([LT_CURRENT])
AC_SUBST([LT_REVISION])
AC_SUBST([LT_AGE])

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
  lib/libnghq.pc
  lib/Makefile
  include/nghq/Makefile
  tests/Makefile
  examples/Makefile
])

AC_OUTPUT
