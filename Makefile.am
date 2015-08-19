ACLOCAL_AMFLAGS = -I m4

SUBDIRS = doc lib man src tests/nl

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
if SYSTEMD
systemdsystemunitdir = @SYSTEMD_SYSTEMUNITDIR@
systemdsystemunit_DATA = dist/matchd.service

defaultsdir = /etc/default
defaults_DATA = dist/default/matchd
endif
