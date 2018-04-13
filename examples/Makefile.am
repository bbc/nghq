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

noinst_PROGRAMS =
if HAVE_LIBEV
noinst_PROGRAMS += multicast-receiver multicast-sender
endif
AM_LDFLAGS = $(top_builddir)/lib/libnghq.la
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
multicast_receiver_LDADD = \
	$(LIBEV_LIBS)
multicast_receiver_CFLAGS = \
	$(LIBEV_CFLAGS)
multicast_receiver_SOURCES = \
	multicast_interfaces.c \
	multicast_interfaces.h \
	multicast-receiver.c
multicast_sender_LDADD = \
	$(LIBEV_LIBS)
multicast_sender_CFLAGS = \
	$(LIBEV_CFLAGS)
multicast_sender_SOURCES = \
	multicast_interfaces.c \
	multicast_interfaces.h \
	multicast-sender.c

