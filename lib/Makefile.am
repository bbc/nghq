#nghq

#
# Copyright (c) 2018 British Broadcasting Corporation
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
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
	tcp2_callbacks.c \
	multicast.c \
	io_buf.c \
	stream_types.c \
	nghq.c

HDRS = \
	frame_creator.h \
	frame_parser.h \
	frame_types.h \
	header_compression.h \
	map.h \
	nghq_internal.h \
	tcp2_callbacks.h \
	multicast.h \
	io_buf.h \
	stream_types.h \
	util.h

libnghq_la_CFLAGS = -I$(top_srcdir)/include $(NGTCP2_CFLAGS) $(NGHTTP2_CFLAGS)
libnghq_la_LIBADD = $(NGTCP2_LIBS) $(NGHTTP2_LIBS)
libnghq_la_SOURCES = $(HDRS) $(OBJECTS)
libnghq_la_LDFLAGS = -no-undefined \
    -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)
