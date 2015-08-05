ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib man src tests/nl

SYSTEMDSYSTEM=$(shell pkg-config systemd --variable=systemdsystemunitdir)

install-systemd:
	install -d -D -m 0755 $(DESTDIR)$(SYSTEMDSYSTEM)
	install -m 0644 dist/matchd.service $(DESTDIR)$(SYSTEMDSYSTEM)/matchd.service

include_HEADERS = $(top_srcdir)/include/backend.h \
                  $(top_srcdir)/include/matchd_lib.h \
                  $(top_srcdir)/include/matchlib.h \
                  $(top_srcdir)/include/matchlib_nl.h \
                  $(top_srcdir)/include/ieslib.h \
                  $(top_srcdir)/include/matlog.h \
                  $(top_srcdir)/include/if_match.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dist/match-interface.pc \
                 dist/matchd-api.pc

defaultsdir = /etc/default
defaults_DATA = dist/default/matchd

install: install-recursive install-systemd
