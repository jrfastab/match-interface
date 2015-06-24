ACLOCAL_AMFLAGS = -I m4

SUBDIRS = lib man src

include_HEADERS = $(top_srcdir)/include/backend.h \
                  $(top_srcdir)/include/matchd_lib.h \
                  $(top_srcdir)/include/matchlib.h \
                  $(top_srcdir)/include/matchlib_nl.h \
                  $(top_srcdir)/include/ieslib.h \
                  $(top_srcdir)/include/if_match.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dist/match-interface.pc \
                 dist/matchd-api.pc
