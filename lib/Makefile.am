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
	version.c \
	quic_transport.c \
	nghq.c

HDRS = \
	debug.h \
	frame_creator.h \
	frame_parser.h \
	frame_types.h \
	header_compression.h \
	lang.h \
	map.h \
	nghq_internal.h \
	tcp2_callbacks.h \
	multicast.h \
	io_buf.h \
	quic_transport.h \
	util.h

libnghq_la_CFLAGS = -I$(top_srcdir)/include $(NGTCP2_CFLAGS) -I$(top_srcdir)/ls-qpack
libnghq_la_LIBADD = $(NGTCP2_LIBS) -L$(top_builddir)/ls-qpack-build -lls-qpack
libnghq_la_SOURCES = $(HDRS) $(OBJECTS)
nodist_libnghq_la_SOURCES = git-version.h
libnghq_la_LDFLAGS = -no-undefined \
    -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE)

BUILT_SOURCES = git-version.h
.PHONY: FORCE
git-version.h:  FORCE
	@echo '#ifndef _GIT_VERSION_H_' > $@.new
	@echo '#define _GIT_VERSION_H_' >> $@.new
	@echo '#define PACKAGE_REVISION "'`if test -d "$(top_srcdir)/.git"; then (cd "$(top_srcdir)"; git describe --always --dirty); else echo "$(PACKAGE_CONFIGURE_REVISION)"; fi`'"' >> $@.new
	@echo '#endif' >> $@.new
	@diff -q $@.new $@ 2>/dev/null && rm -f $@.new || mv -f $@.new $@

CLEANFILES = git-version.h
