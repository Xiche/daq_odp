#												-*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.62)
AC_INIT([daq_odp], [1.0], [xiche@verizon.net])
AM_INIT_AUTOMAKE()
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([daq_odp.c])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_LIBTOOL

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
AC_ARG_WITH([odp_includes],
            [  --with-odp-includes=DIR          OpenDataPlane include directory],
            [with_odp_includes="$withval"], [with_odp_includes="no"])

if test "x$with_odp_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_odp_includes}"
fi

AC_CHECK_HEADERS([odp.h], [], [AC_MSG_ERROR([OpenDataPlane headers are missing!])])

AC_ARG_WITH([odp_libraries],
            [  --with-odp-libraries=DIR         OpenDataPlane library directory],
            [with_odp_libraries="$withval"], [with_odp_libraries="no"])

if test "x$with_odp_libraries" != "xno"; then
    LDFLAGS="${CPPFLAGS} -L${with_odp_libraries}"
fi

AC_CHECK_LIB([odp], [odp_init_global], [], [AC_MSG_FAILURE([OpenDataPlane libraries are missing!])])

# Substitutions
AC_SUBST([LIBS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([CFLAGS])
AC_SUBST([AM_LDFLAGS])

# Output
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
