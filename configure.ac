#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(yixun, 1.1, gmshake@gmail.com)
AC_CONFIG_SRCDIR([gre-config/main.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE

# Checks for programs.
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_CPP
AC_PROG_MKDIR_P
#AC_PROG_RANLIB

# Checks for libraries.
# FIXME: Replace `main' with a function in `-liconv':
AC_CHECK_LIB([iconv], [iconv])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/ioctl.h sys/socket.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm atexit bzero ftruncate inet_ntoa memset select socket stpcpy strchr strerror strstr])

AC_CONFIG_FILES([Makefile
                 gre-config/Makefile
                 src/Makefile])
AC_OUTPUT
