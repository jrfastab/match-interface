if FMIESINCS
IES_INC_BASE = @IESINCS@
IES_CFLAGS = -DFM_SUPPORT_FM10000 -D_FM_ARCH_X86_64 \
             -I$(IES_INC_BASE) \
             -I$(IES_INC_BASE)/alos \
             -I$(IES_INC_BASE)/alos/linux \
             -I$(IES_INC_BASE)/std/intel \
             -I$(IES_INC_BASE)/common \
             -I$(IES_INC_BASE)/platforms \
             -I$(IES_INC_BASE)/platforms/libertyTrail -lrt
else
IES_CFLAGS = -DFM_SUPPORT_FM10000 -D_FM_ARCH_X86_64 -lrt \
             $(IESAPI_CFLAGS)
endif

WARNING_FLAGS_GCC = -pedantic -Wall -Wextra -Wwrite-strings -Wformat=2 \
                    -Wlogical-op -Wpointer-arith -Wfloat-equal \
                    -Wnested-externs -Wbad-function-cast \
                    -Wcast-qual -Wcast-align -Wstrict-prototypes \
                    -Wmissing-declarations -Wmissing-include-dirs \
                    -Wdeclaration-after-statement -Wmissing-prototypes \
                    -Wold-style-definition

AM_CFLAGS = -std=c99 -O2 -D_GNU_SOURCE -Werror $(WARNING_FLAGS_GCC) \
            $(LIBNL_CFLAGS) $(LIBGVC_CFLAGS) -lrt -I$(abs_top_srcdir) \
            -I$(abs_top_srcdir)/include
CFLAGS += $(EXTRA_CFLAGS)

LIBTOOL_DEPS = @LIBTOOL_DEPS@

lib_LTLIBRARIES = libmatchies.la
libmatchies_la_SOURCES = ieslib.c
libmatchies_la_CFLAGS = $(AM_CFLAGS) $(IES_CFLAGS) $(CFLAGS)
libmatchies_la_LDFLAGS = -release @MATCH_INTERFACE_VERSION@

lib_LTLIBRARIES += libmatchbpf.la
libmatchbpf_la_SOURCES = bpflib.c
libmatchbpf_la_CFLAGS = $(AM_CFLAGS) $(IES_CFLAGS) $(CFLAGS)
libmatchbpf_la_LDFLAGS = -release @MATCH_INTERFACE_VERSION@

lib_LTLIBRARIES += libmatch.la
libmatch_la_SOURCES = matchlib_nl.c matchlib.c matlog.c
libmatch_la_LDFLAGS = -release @MATCH_INTERFACE_VERSION@

lib_LTLIBRARIES += libmatchd.la
libmatchd_la_SOURCES = matchd_lib.c backend.c
libmatchd_la_CFLAGS = $(AM_CFLAGS) $(IES_CFLAGS) $(CFLAGS)
libmatchd_la_LDFLAGS = -release @MATCH_INTERFACE_VERSION@
