AC_INIT([match-interface], [0.0.2])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_PROG_CC
LT_INIT()
AC_SUBST([LIBTOOL_DEPS])
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-genl-3.0 libnl-route-3.0])
PKG_CHECK_MODULES([LIBNL_3_2_22], [libnl-3.0 >= 3.2.22], [AC_DEFINE([HAVE_NLA_NEST_CANCEL], 1)], [AC_DEFINE([HAVE_NLA_NEST_CANCEL], 0)])
PKG_CHECK_MODULES([IESAPI], [ies-api], [HAVE_IESAPI=1], [HAVE_IESAPI=0])
PKG_CHECK_MODULES([LIBGVC], [libgvc >= 2.30.0])
AC_PREFIX_DEFAULT(/usr/local)
AC_SUBST([MATCH_INTERFACE_VERSION], [AC_PACKAGE_VERSION])
test "x$prefix" = "xNONE" && prefix=$ac_default_prefix
test "x$exec_prefix" = "xNONE" && exec_prefix=$prefix
SBINDIR=`eval echo $sbindir`
AC_SUBST(SBINDIR)
SYSCONFDIR=`eval echo $sysconfdir`
AC_SUBST(SYSCONFDIR)

IESINCS=
AC_ARG_WITH(
    [ies-api-headers],
    AS_HELP_STRING(
        [--with-ies-api-headers=FULLPATH],
        [Path to IES API headers (default: prefix/include)]
    ),
    [IESINCS="$withval"]
)
AC_SUBST(IESINCS)
IESLIBS=
AC_ARG_WITH(
    [ies-api-libraries],
    AS_HELP_STRING(
        [--with-ies-api-libraries=FULLPATH],
        [Path to IES API libraries (default: prefix/lib)]
    ),
    [IESLIBS="$withval"]
)
AC_SUBST(IESLIBS)

AS_IF([test "$HAVE_IESAPI" == 0 && test "x$IESINCS" == "x"],
      [AC_MSG_ERROR([Make sure ies-api is installed or provide --with-ies-api-headers])])
AS_IF([test "$HAVE_IESAPI" == 0 && test "x$IESLIBS" == "x"],
      [AC_MSG_ERROR([Make sure ies-api is installed or provide --with-ies-api-libraries])])

AM_CONDITIONAL([FMIESINCS], [test "x$IESINCS" != x])
AM_CONDITIONAL([FMIESLIBS], [test "x$IESLIBS" != x])

CFLAGS="$CFLAGS -Wl,--no-as-needed"

AC_ARG_ENABLE(
    [systemd],
    AC_HELP_STRING(
        [--disable-systemd],
        [Disable systemd integration]
    ),
    [enable_systemd=${enableval}]
)
AM_CONDITIONAL(SYSTEMD, test "${enable_systemd}" != no)

AC_ARG_WITH(
    [systemdsystemunitdir],
    AC_HELP_STRING(
        [--with-systemdsystemunitdir=DIR],
        [Path to the systemd system unit directory]
    ),
    [path_systemunitdir=${withval}]
)
if ( test "${enable_systemd}" != "no" && test -z "${path_systemunitdir}"); then
    AC_MSG_CHECKING([systemd system unit dir])
    path_systemunitdir="`$PKG_CONFIG systemd --variable=systemdsystemunitdir`"
    if (test -z "${path_systemunitdir}"); then
        AC_MSG_ERROR([systemd system unit directory is required with systemd])
    fi
    AC_MSG_RESULT([${path_systemunitdir}])
fi
AC_SUBST(SYSTEMD_SYSTEMUNITDIR, [${path_systemunitdir}])

AC_CONFIG_FILES([
Makefile lib/Makefile man/Makefile src/Makefile tests/nl/Makefile
dist/match-interface.pc
dist/matchd-api.pc
dist/matchd.service
dist/match-interface.spec])

dnl Enable/disable documentation build
AC_ARG_ENABLE([doc],
    AS_HELP_STRING(
        [--enable-doc],
        [Build API documentation (default: no)]),
    [case "${enableval}" in
        yes) doc=yes ;;
        no)  doc=no ;;
        *)   AC_MSG_ERROR([invalid value ${enableval} for --enable-doc]);;
     esac], [doc=no])
AM_CONDITIONAL([BUILD_DOC], [test x$doc = xyes])

dnl Check for doxygen
AC_CHECK_PROGS([DOXYGEN], [doxygen])
AS_IF([test -z "$DOXYGEN" && test x$doc = xyes],
      [AC_MSG_FAILURE(Cannot build documentation without doxygen)])

AC_CONFIG_FILES([doc/doxyfile doc/Makefile])

AC_OUTPUT

