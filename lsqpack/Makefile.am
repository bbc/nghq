# https://www.gnu.org/software/automake/manual/automake.html#Sources
BUILT_SOURCES = lsqpack-build
lsqpack-build:
	[ -d ls-qpack-build ] || mkdir -p ls-qpack-build
	cd ls-qpack-build; \
	CFLAGS="$(CFLAGS)" LDFLAGS="$(LDFLAGS)" \
		$(CMAKE) -DBUILD_SHARED_LIBS=ON ${abs_top_srcdir}/ls-qpack;
.PHONY: lsqpack-build

all:	lsqpack-build
	cd ls-qpack-build; \
	make

dist-hook:
	cp -r $(top_srcdir)/ls-qpack $(top_distdir)/ls-qpack

install-exec-local:
	[ -d "$(DESTDIR)$(libdir)" ] || mkdir -p "$(DESTDIR)$(libdir)"
	cp ls-qpack-build/libls-qpack.so* "$(DESTDIR)$(libdir)"/

clean-local: lsqpack-build
	cd ls-qpack-build; \
	make clean

distclean-local:
	rm -rf ls-qpack-build
