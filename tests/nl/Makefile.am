if FMIESINCS
IES_INC_BASE = @IESINCS@
IES_CFLAGS = -DFM_SUPPORT_FM10000 -D_FM_ARCH_X86_64 \
             -I$(IES_INC_BASE) \
             -I$(IES_INC_BASE)/alos \
             -I$(IES_INC_BASE)/alos/linux \
             -I$(IES_INC_BASE)/std/intel \
             -I$(IES_INC_BASE)/common \
             -I$(IES_INC_BASE)/platforms \
             -I$(IES_INC_BASE)/platforms/libertyTrail
else
IES_CFLAGS = -DFM_SUPPORT_FM10000 -D_FM_ARCH_X86_64 \
             $(IESAPI_CFLAGS)
endif
if FMIESLIBS
IES_LIB_BASE = @IESLIBS@
IES_LIBS = -L$(IES_LIB_BASE) \
           -lFocalpointSDK -lLTStdPlatform -ldl
else
IES_LIBS = $(IESAPI_LIBS)
endif


WARNING_FLAGS_GCC = -pedantic -Wall -Wextra -Wwrite-strings -Wformat=2 \
                    -Wlogical-op -Wpointer-arith -Wfloat-equal \
                    -Wnested-externs -Wbad-function-cast -Wconversion \
                    -Wcast-qual -Wcast-align -Wstrict-prototypes \
                    -Wmissing-declarations -Wmissing-include-dirs \
                    -Wdeclaration-after-statement -Wmissing-prototypes \
                    -Wold-style-definition

AM_CFLAGS = -std=c99 -O2 -D_GNU_SOURCE -Werror $(WARNING_FLAGS_GCC) \
            $(LIBNL_CFLAGS) $(LIBGVC_CFLAGS) -I$(abs_top_srcdir) \
            -I$(abs_top_srcdir)/include
CFLAGS += $(EXTRA_CFLAGS)

AM_LDFLAGS = $(LIBNL_LIBS) $(LIBGVC_LIBS)


sbin_PROGRAMS = nl_get_attr_ex
nl_get_attr_ex_LDADD = $(abs_top_builddir)/lib/libmatch.la \
             $(abs_top_builddir)/lib/libmatchies.la \
             $(abs_top_builddir)/lib/libmatchd.la \
             $(IES_LIBS)
nl_get_attr_ex_CFLAGS = $(AM_CFLAGS) $(IES_CFLAGS) $(CFLAGS)
nl_get_attr_ex_SOURCES = nl_get_attr_ex.c

