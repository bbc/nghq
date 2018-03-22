#nghq

#
# TODO: Add license preamble
#

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libnghq.pc
DISTCLEANFILES = $(pkgconfig_DATA)

lib_LTLIBRARIES = libnghq.la

OBJECTS = \
	frame_creator.c \
	frame_parser.c \
	header_compression.c \
	map.c \
	util.c \
	nghq.c

HDRS = \
	frame_creator.h \
	frame_parser.h \
	frame_types.h \
	header_compression.h \
	map.h \
	nghq_internal.h \
	util.h

libnghq_la_CFLAGS = -I$(top_srcdir)/include $(NGTCP2_CFLAGS) $(NGHTTP2_CFLAGS)
libnghq_la_LIBADD = $(NGTCP2_LIBS) $(NGHTTP2_LIBS)
libnghq_la_SOURCES = $(HDRS) $(OBJECTS)
libnghq_la_LDFLAGS = -no-undefined \
    -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
