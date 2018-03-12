#nghq

#
# TODO: Add license preamble
#

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnghq.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libnghq.la

OBJECTS = \
    nghq.c

HDRS =

libnghq_la_CFLAGS = -I$(top_srcdir)/include

libnghq_la_SOURCES = $(HDRS) $(OBJECTS)
libnghq_la_LDFLAGS = -no-undefined \
    -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
