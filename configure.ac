dnl DNL lines are comment lines
dnl AC_INIT name version
AC_INIT([match-interface], [0.0.1])
dnl Custom M4 macros need to be added to the ./m4 directory to be
dnl detected here. This dir is currently not created as no m4 macros are
dnl currently used.
AC_CONFIG_MACRO_DIR([m4])
dnl Put auxilary files in build-aux
AC_CONFIG_AUX_DIR([build-aux])
dnl Initialize automake for makefile.am files
dnl foreign strictness
dnl subdir-objects Build objects in subdirectories
AM_INIT_AUTOMAKE([foreign subdir-objects])
dnl Set the compiler program to c compiler (cc)
AC_PROG_CC
dnl Initilize libtool
LT_INIT()
dnl Replace @LIBTOOL_DEPS@ in processed files with ld dependency options
AC_SUBST([LIBTOOL_DEPS])
dnl Search for libnl with pkg-config
PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-genl-3.0 libnl-route-3.0])
dnl Search for the IES API with pkg-config
PKG_CHECK_MODULES([IESAPI], [ies-api], [HAVE_IESAPI=1], [HAVE_IESAPI=0])
dnl Search for graphviz libraries with pkg-config
PKG_CHECK_MODULES([LIBGVC], [libgvc >= 2.30.0])
dnl Set the default installation path to /usr/local per LFS standards
AC_PREFIX_DEFAULT(/usr/local)
dnl Replace @MATCH_INTERFACE_VERSION@ in processed files with the package version
dnl specified in AC_INIT
AC_SUBST([MATCH_INTERFACE_VERSION], [AC_PACKAGE_VERSION])
dnl Replace @SBINDIR@ and @SYSCONFDIR@ in integration files
test "x$prefix" = "xNONE" && prefix=$ac_default_prefix
test "x$exec_prefix" = "xNONE" && exec_prefix=$prefix
SBINDIR=`eval echo $sbindir`
AC_SUBST(SBINDIR)
SYSCONFDIR=`eval echo $sysconfdir`
AC_SUBST(SYSCONFDIR)

dnl Provide the ability to specifiy the path to the IES API header files
dnl in case they are not installed on the system with pkg-config support.
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
dnl Provide the ability to specifiy the path to the IES API libraries in case
dnl they are not installed on the system with pkg-config support.
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

dnl Test if the IES API was found anywher above. If it wasn't fail out.
AS_IF([test "$HAVE_IESAPI" == 0 && test "x$IESINCS" == "x"],
      [AC_MSG_ERROR([Make sure ies-api is installed or provide --with-ies-api-headers])])
AS_IF([test "$HAVE_IESAPI" == 0 && test "x$IESLIBS" == "x"],
      [AC_MSG_ERROR([Make sure ies-api is installed or provide --with-ies-api-libraries])])

dnl Allow makefiles to test if configure.ac found needed things by providing
dnl true/false variables.
AM_CONDITIONAL([FMIESINCS], [test "x$IESINCS" != x])
AM_CONDITIONAL([FMIESLIBS], [test "x$IESLIBS" != x])

CFLAGS="$CFLAGS -Wl,--no-as-needed"

dnl Process makefiles and any other files that need to be. This takes a
dnl file.in (Makefile.in) and processes it correctly to the name specified
dnl below.
AC_CONFIG_FILES([
Makefile lib/Makefile man/Makefile src/Makefile tests/nl/Makefile
dist/match-interface.pc
dist/matchd-api.pc
dist/match-interface.spec])
AC_OUTPUT

