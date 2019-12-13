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

SUBDIRS = lib include/nghq tests examples

ACLOCAL_AMFLAGS = -I m4

# https://www.gnu.org/software/automake/manual/automake.html#Sources
BUILT_SOURCES = lsqpack
lsqpack:
	[ -d ls-qpack-build ] || mkdir ls-qpack-build; \
	cd ls-qpack-build; \
	cmake -DBUILD_SHARED_LIBS=ON -E env CFLAGS=\"$(CFLAGS)\" \
			LDFLAGS=\"$(LDFLAGS)\" ${abs_top_srcdir}/ls-qpack; \
	make

install-exec-hook:
	cp ${top_builddir}/ls-qpack-build/libls-qpack.so* $(DESTDIR)$(libdir)/

clean-local:
	cd ls-qpack-build; \
	make clean

distclean-local:
	rm -rf ls-qpack-build

.PHONY: lsqpack
