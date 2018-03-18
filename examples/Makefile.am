noinst_PROGRAMS =
if HAVE_LIBEV
noinst_PROGRAMS += example-client example-server
endif
AM_LDFLAGS = $(top_builddir)/lib/libnghq.la
AM_CPPFLAGS = -I$(top_srcdir)/include -I$(top_builddir)/include
example_client_LDADD = \
	$(LIBEV_LIBS)
example_client_CFLAGS = \
	$(LIBEV_CFLAGS)
example_client_SOURCES = \
	example-client.c
example_server_LDADD = \
	$(LIBEV_LIBS)
example_server_CFLAGS = \
	$(LIBEV_CFLAGS)
example_server_SOURCES = \
	example-server.c

