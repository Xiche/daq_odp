#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([daq_odp],[1.0],[xiche@verizon.net])
AM_INIT_AUTOMAKE()
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([daq_odp.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
LT_INIT

# Find pkg-config
PKG_PROG_PKG_CONFIG

# Enable visibility if we can
AC_ENABLE_VISIBILITY()
# Special compiler flags for ICC, etc.
AC_SF_COMPILER_SETUP()

# Checks for the DAQ API headers and the SFBPF headers/library.
AC_CHECK_DAQ_API
AC_CHECK_SFBPF

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h stdint.h stdlib.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strchr strdup strerror strtol])

# Custom include/library path specifications

AC_MSG_CHECKING([for libodp-linux pkg-config presence])
PKG_CHECK_EXISTS([libodp-linux], [have_odp_pkgconfig="yes"], [have_odp_pkgconfig="no"])
AC_MSG_RESULT(${have_odp_pkgconfig})

if test "${have_odp_pkgconfig}" = "yes" ; then
    ODP_CFLAGS=`${PKG_CONFIG} --cflags libodp-linux`
    ODP_LDFLAGS=`${PKG_CONFIG} --libs-only-L libodp-linux`
fi

AC_ARG_WITH([odp_includes],
            [  --with-odp-includes=DIR          OpenDataPlane include directory],
            [with_odp_includes="$withval"], [with_odp_includes="no"])

if test "x$with_odp_includes" != "xno"; then
    ODP_CFLAGS="-I${with_odp_includes}"
fi

AC_ARG_WITH([odp_libraries],
            [  --with-odp-libraries=DIR         OpenDataPlane library directory],
            [with_odp_libraries="$withval"], [with_odp_libraries="no"])

if test "x$with_odp_libraries" != "xno"; then
    ODP_LDFLAGS="-L${with_odp_libraries}"
fi

CPPFLAGS="${CPPFLAGS} ${ODP_CFLAGS}"
LDFLAGS="${LDFLAGS} ${ODP_LDFLAGS}"

AC_CHECK_HEADERS([odp.h], [], [AC_MSG_FAILURE([cannot find OpenDataPlane headers!])])
AC_CHECK_LIB([odp-linux], [odp_init_global], [], [AC_MSG_FAILURE([cannot find OpenDataPlane libraries!])])

# Substitutions
AC_SUBST([LIBS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AC_MSG_RESULT([
    $PACKAGE $VERSION
    ========

    prefix:         ${prefix}
    sysconfdir:     ${sysconfdir}
    libdir:         ${libdir}
    includedir:     ${includedir}

    compiler:       ${CC}
    cflags:         ${CFLAGS}
    cppflags:       ${CPPFLAGS}
    ldflags:        ${LDFLAGS}
    libs:           ${LIBS}

    am_cppflags:    ${AM_CPPFLAGS}
    am_cflags:      ${AM_CFLAGS}
    am_ldflags:     ${AM_LDFLAGS}
])
