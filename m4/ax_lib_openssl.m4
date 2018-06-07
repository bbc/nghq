# ===========================================================================
#
# SYNOPSIS
#
#   AX_LIB_OPENSSL([VERSION],[ACTION-IF-FOUND],[ACTION-IF-NOT-FOUND])
#
# DESCRIPTION
#
#   Checks for OpenSSL pkg-config. If successful and provided
#   expand ACTION-IF-FOUND, otherwise expand ACTION-IF-NOT-FOUND, or, if
#   omitted, error out like pkg-config does.
#
#   Defines openssl_LIBS and openssl_CFLAGS.
#
# LICENSE
#
#   Copyright (c) 2018 British Broadcasting Corporation
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

AU_ALIAS([AC_CHECK_OPENSSL], [AX_LIB_OPENSSL])
AC_DEFUN([AX_LIB_OPENSSL], [
	pushdef([VERSION], [m4_default([$1], [>= 1.0.1])])
	pushdef([ACTION_IF_FOUND], [$2])
	pushdef([ACTION_IF_NOT_FOUND], [$3])

	AC_CACHE_VAL([ax_cv_feat_openssl], [
		## assume failure
		ax_cv_feat_openssl="no"

		PKG_CHECK_MODULES([openssl], [openssl ]VERSION[], [
			ACTION_IF_FOUND
		], [
			m4_default([]ACTION_IF_NOT_FOUND[], [AC_MSG_ERROR([dnl
Package requirements (openssl version) were not met.

Consider adjusting the PKG_CONFIG_PATH environment variable if you
installed software in a non-standard prefix.

Alternatively, you may set the environment variables openssl_CFLAGS
and openssl_LIBS to avoid the need to call pkg-config.
See the pkg-config man page for more details.])
			])
		])
	])

	popdef([ACTION_IF_NOT_FOUND])
	popdef([ACTION_IF_FOUND])
	popdef([VERSION])
])dnl AX_LIB_OPENSSL
