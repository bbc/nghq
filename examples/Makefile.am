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
	multicast-receiver.c
multicast_sender_LDADD = \
	$(LIBEV_LIBS)
multicast_sender_CFLAGS = \
	$(LIBEV_CFLAGS)
multicast_sender_SOURCES = \
	multicast-sender.c

