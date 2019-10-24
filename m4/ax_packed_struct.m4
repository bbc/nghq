# ===========================================================================
#        https://www.gnu.org/software/autoconf-archive/ax_lib_ev.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PACKED_STRUCT
#
# DESCRIPTION
#
#   Checks for how the compiler creates packed structures.
#
#   Defines HAVE_FUNC_ATTRIBUTE_PACKED if __attribute__((packed)) is available.
#   Defines HAVE_PRAGMA_PACK if #pragma pack(n) is available.
#   Defines HAVE_PACKED_ATTRIBUTE if __packed is available.
#   Defines NO_PACKING=1 if there is no compiler support for packing.
#
# LICENSE
#
#   Copyright (c) 2019 British Broadcasting Corporation
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 1

AC_DEFUN([AX_ATTRIBUTE_PACKED],[
  AC_CACHE_CHECK([for __attribute__((packed))], [ax_cv___attribute__packed],
    [AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM(
	[[#include <stdlib.h>
          struct to_pack {
              unsigned char abyte;
              short s_array[2] __attribute__ ((packed));
          };
        ]], [static struct to_pack packed_values = { 0U, {1, 1} };])],
      [ax_cv___attribute__packed=yes],
      [ax_cv___attribute__packed=no]
    )
  ])
  AS_IF([test "$ax_cv___attribute__packed" = "yes"], [
    AC_DEFINE([HAVE_FUNC_ATTRIBUTE_PACKED], 1, [define if your compiler has __attribute__ ((packed))])
  ])
])

AC_DEFUN([AX_PRAGMA_PACK],[
  AC_CACHE_CHECK([[for #pragma pack()]], [ax_cv_pragma_pack],
    [AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM(
        [[#include <stdlib.h>
          #pragma push
          #pragma pack(1)
          struct to_pack {
              unsigned char abyte;
              short s_array[2];
          };
          #pragma pop
        ]], [static struct to_pack packed_values = { 0U, {1, 1} };])],
      [ax_cv_pragma_pack=yes],
      [ax_cv_pragma_pack=no]
    )
  ])
  AS_IF([test "$ax_cv_pragma_pack" = "yes"], [
    AC_DEFINE([HAVE_PRAGMA_PACK], 1, [define if your compiler has #pragma pack()])
  ])
])

AC_DEFUN([AX_C_PACKED_ATTRIBUTE],[
  AC_CACHE_CHECK([for __packed], [ax_cv_packed_attribute],
    [AC_COMPILE_IFELSE(
      [AC_LANG_PROGRAM(
        [[#include <stdlib.h>
          struct to_pack {
              unsigned char abyte;
              short s_array[2] __packed;
          };
        ]], [static struct to_pack packed_values = { 0U, {1, 1} };])],
      [ax_cv_packed_attribute=yes],
      [ax_cv_packed_attribute=no]
    )
  ])
  AS_IF([test "$ax_cv_packed_attribute" = "yes"], [
    AC_DEFINE([HAVE_PACKED_ATTRIBUTE], 1, [define if your compiler has __packed])
  ])
])

AC_DEFUN([AX_PACKED_STRUCT], [
	AX_ATTRIBUTE_PACKED
	AX_PRAGMA_PACK
	AX_C_PACKED_ATTRIBUTE
	AS_IF([test "$ax_cv___attribute__packed" = "no" -a "$ax_cv_pragma_pack" = "no" -a "$ax_cv_packed_attribute" = "no"], [
		AC_DEFINE([NO_PACKED], 1, [define if your compiler does nt have a recognised way of packing structures])
        ])
])
