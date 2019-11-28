AC_DEFUN([AX_PACKAGE_VERSION], [
  [PACKAGE_VERSION_MAJOR=`echo "$PACKAGE_VERSION" | sed 's/\..*//;s/[^0-9]//g'`]
  [PACKAGE_VERSION_MINOR=`echo "$PACKAGE_VERSION" | sed 's/^[^.]*\.//;s/\..*//;s/[^0-9]//g'`]
  [PACKAGE_VERSION_MICRO=`echo "$PACKAGE_VERSION" | sed 's/^[^.]*\.[^.]*\.//;s/\..*//;s/[^0-9]//g'`]
  AC_DEFINE_UNQUOTED([PACKAGE_VERSION_MAJOR], [$PACKAGE_VERSION_MAJOR], [Library package major version number])
  AC_DEFINE_UNQUOTED([PACKAGE_VERSION_MINOR], [$PACKAGE_VERSION_MINOR], [Library package minor version number])
  AC_DEFINE_UNQUOTED([PACKAGE_VERSION_MICRO], [$PACKAGE_VERSION_MICRO], [Library package micro version number])
  AC_SUBST(PACKAGE_VERSION_MAJOR)
  AC_SUBST(PACKAGE_VERSION_MINOR)
  AC_SUBST(PACKAGE_VERSION_MICRO)
])
