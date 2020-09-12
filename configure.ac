AC_PREREQ(2.60)
AC_INIT([mcrx],
        [1],
        [jakeholland.net@gmail.com],
        [mcrx],
        [http://github.com/GrumpyOldTroll/libmcrx])
AC_CONFIG_SRCDIR([src/libmcrx.c])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_LIBOBJ_DIR([portable])
AM_INIT_AUTOMAKE([check-news foreign 1.11 -Wall -Werror -Wno-portability silent-rules tar-pax no-dist-gzip dist-xz subdir-objects])
AM_MAINTAINER_MODE
AC_PROG_CC_STDC
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_CONFIG_MACRO_DIR([m4])
AM_SILENT_RULES([yes])
LT_INIT([disable-static pic-only])
AC_PREFIX_DEFAULT([/usr])

AC_PROG_SED
AC_PROG_MKDIR_P

AC_ARG_ENABLE([logging],
        AS_HELP_STRING([--disable-logging], [disable system logging @<:@default=enabled@:>@]),
        disable_logging=yes, [])
AS_IF([test "x$disable_logging" = "xyes"], [
        AC_DEFINE(DISABLE_LOGGING, [1], [System logging.])
])

AC_PATH_PROG([CPPLINT], [cpplint], [true])
AS_IF([test "x$CPPLINT" = xtrue],
    [AC_MSG_WARN([We recommend cpplint for developing this package.
Get it from 'pip install cpplint' or https://github.com/cpplint/cpplint])])

AC_ARG_ENABLE([debug],
        AS_HELP_STRING([--enable-debug], [enable debug messages @<:@default=disabled@:>@]),
        [], [disable_debug=yes])
AS_IF([test "x$disable_debug" = "xyes"], [
        AC_DEFINE(DISABLE_DEBUG, [1], [Debug messages.])
])

#AC_CHECK_HEADER([event.h],
#     [AC_DEFINE([HAVE_EVENT_H], [1], [Define to 1 if you have <event.h>.])],
#     [AC_MSG_ERROR([could not include <event.h>. You need to install libevent-dev or build from https://github.com/libevent/libevent.git and set C_INCLUDE_PATH and LIBRARY_PATH])])
#
#AC_CHECK_LIB([event],[event_base_new],
#	[AC_DEFINE([HAVE_EVENT_LIB], [1], [Define to 1 if you have libevent])],
#	[AC_MSG_ERROR([could not invoke event_base_new with -levent, you need to install libevent-dev or build from https://github.com/libevent/libevent.git and set C_INCLUDE_PATH and LIBRARY_PATH])])
#
#AC_CHECK_HEADER([dns_sd.h],
#     [AC_DEFINE([HAVE_DNSSD_H], [1], [Define to 1 if you have <dns_sd.h>.])],
#     [AC_MSG_ERROR([could not include <dns_sd.h>. You need to install libavahi-compat-libdnssd-dev or build from https://github.com/IETF-Hackathon/mDNSResponder.git (mDNSPosix) and set C_INCLUDE_PATH and LIBRARY_PATH])])

# commenting for mac.  it's not libdns_sd, it's part of system libraries,
# so there needs to be a mac/other special case.
#AC_CHECK_LIB([dns_sd],[DNSServiceRegister],
#	[AC_DEFINE([HAVE_DNSSD_LIB], [1], [Define to 1 if you have libdns_sd])],
#	[AC_MSG_ERROR([could not load libdns_sd.so. You need to install mdnsd or build from https://github.com/IETF-Hackathon/mDNSResponder.git (mDNSPosix) and set C_INCLUDE_PATH and LIBRARY_PATH])])

my_CFLAGS="-pedantic -Wall -Wextra \
-Wmissing-declarations -Wmissing-prototypes \
-Wnested-externs -Wsign-compare \
-Wstrict-prototypes -Wshadow \
-Wformat-security"
AC_SUBST([my_CFLAGS])

AC_CONFIG_HEADERS(config.h)
AC_CONFIG_FILES([
        Makefile
])

AC_OUTPUT
AC_MSG_RESULT([
        $PACKAGE $VERSION
        =====

        prefix:                 ${prefix}
        sysconfdir:             ${sysconfdir}
        libdir:                 ${libdir}
        includedir:             ${includedir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}

        logging:                ${enable_logging}
        debug:                  ${enable_debug}
])
