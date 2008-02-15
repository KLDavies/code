
AC_INIT([SSDEEP],[1.2],[research@jessekornblum.com])
AM_INIT_AUTOMAKE

AC_CONFIG_FILES([Makefile])
AM_CONFIG_HEADER([config.h])

AC_CANONICAL_HOST

AC_PROG_CC
AC_LIBTOOL_WIN32_DLL
#AC_PROG_LIBTOOL
AM_PROG_LIBTOOL
AC_PROG_INSTALL

case $host in
  *-*-*linux*-*) AC_DEFINE([__LINUX__],1,[Linux operating system functions]) ;;
  *-*-mingw32)   LIBS="-liberty $LIBS" && CPPFLAGS="-DUNICODE -D_UNICODE $CPPFLAGS"
esac


# Bring additional directories where things might be found into our
# search path. I don't know why autoconf doesn't do this by default
for spfx in /usr/local /opt/local /sw ; do
    echo checking ${spfx}/include
    if test -d ${spfx}/include; then
        CPPFLAGS="-I${spfx}/include $CPPFLAGS"
        LDFLAGS="-L${spfx}/lib $LDFLAGS"
    fi
done

AC_C_BIGENDIAN

AC_CHECK_HEADERS([libgen.h])
# fcntl.h will be added if/when we use AFF
#AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([dirent.h])
AC_CHECK_HEADERS([inttypes.h])

#AC_CHECK_HEADERS([ctype.h])
#AC_CHECK_HEADERS([errno.h])
#AC_CHECK_HEADERS([limits.h])
#AC_CHECK_HEADERS([stdarg.h])

AC_OUTPUT


