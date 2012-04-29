#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.61)
AC_INIT(yixun, 1.4, gmshake@gmail.com)
AC_CONFIG_SRCDIR([src/main.c])
AC_CONFIG_HEADER([config.h])
AM_INIT_AUTOMAKE
AC_CANONICAL_HOST

AC_PROG_AWK
AC_PROG_CC
AC_PROG_CXX
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_MKDIR_P
AC_PROG_RANLIB

# Checks for programs.
AC_ARG_ENABLE(debug, 
			  [AC_HELP_STRING([--enable-debug], [Build a debug version])],
			  [CFLAGS="-DDEBUG -Wall -g -O0"],
			  [CFLAGS="-Wall -O2"]
			 )

case $host_vendor in
	*openwrt*)
	CFLAGS="$CFLAGS -Os"
	;;
esac

# Checks for libraries.
AC_ARG_ENABLE(iconv, 
			  [AC_HELP_STRING([--disable-iconv], [Do NOT compile with iconv])], 
			  [have_iconv="no"], 
			  [have_iconv="yes"], 
			  ,)
if test "x$have_iconv" = "xyes"; then
	case $host_os in
		*bsd*)
		CFLAGS="$CFLAGS -I/usr/local/include"
		LIBS="$LIBS -L/usr/local/lib"
		;;
	esac

	AC_SEARCH_LIBS(iconv_open, iconv, , [AC_SEARCH_LIBS(libiconv_open, iconv, , [have_iconv="no"])])
	if test "x$have_iconv" = "xno"; then
		AC_MSG_WARN([Could not find an iconv implementation, see INSTALL])
		AC_DEFINE([HAVE_ICONV], [0], [Define to 1 if iconv library is installed and enabled])
	else
		AC_DEFINE([HAVE_ICONV], [1], [Define to 1 if iconv library is installed and enabled])
	fi
fi

# Checks for header files.
AC_HEADER_STDBOOL
AC_HEADER_STDC
AC_HEADER_SYS_WAIT

AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h strings.h sys/file.h sys/ioctl.h sys/param.h sys/socket.h syslog.h unistd.h])
if test "x$have_iconv" = "xyes"; then
	AC_CHECK_HEADERS([iconv.h])
fi

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
AC_TYPE_INT32_T
AC_TYPE_INT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([alarm atexit bzero ftruncate inet_ntoa memset select socket stpcpy strcasecmp strchr strerror strlcpy strstr strcasestr])

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 src/Makefile])
AC_OUTPUT
