#ifndef CONFIG_H

#cmakedefine OS_LINUX
#cmakedefine OS_BSD
#cmakedefine OS_BSD_FREE
#cmakedefine OS_BSD_NET
#cmakedefine OS_BSD_OPEN
#cmakedefine OS_DARWIN
#cmakedefine OS_GNU

#cmakedefine WORDS_BIGENDIAN
#cmakedefine OS_SIZEOF_P @OS_SIZEOF_P@

#cmakedefine CC_VERSION "@CC_VERSION@"

#cmakedefine HAVE_SYS_SELECT_H
#cmakedefine HAVE_SYS_POLL_H
#cmakedefine HAVE_UTSNAME_H
#cmakedefine HAVE_STDINT_H
#cmakedefine HAVE_GETOPT_H
#cmakedefine HAVE_ARPA_NAMESER_H
#cmakedefine HAVE_LTDL_H
#cmakedefine HAVE_DLFCN_H
#cmakedefine HAVE_CTYPE_H
#cmakedefine HAVE_INTTYPES_H
#cmakedefine HAVE_MUTEX_RECURSIVE_NP
#cmakedefine HAVE_IP6T_SO_ORIGINAL_DST
#cmakedefine HAVE_LIBGEN_H

#cmakedefine HAVE_PCRE
#cmakedefine HAVE_PCRE2
#cmakedefine HAVE_POLL
#cmakedefine HAVE_STRTOK_R
#cmakedefine HAVE_STRNDUP
#cmakedefine HAVE_SELECT
#cmakedefine HAVE_SCANDIR
#cmakedefine HAVE_STRLCAT
#cmakedefine HAVE_STRLCAT_FUNCTION
#cmakedefine HAVE_STRLCPY
#cmakedefine HAVE_STRLCPY_FUNCTION
#cmakedefine HAVE_STRSEP
#cmakedefine HAVE_STRCASESTR
#cmakedefine HAVE_MEMMEM
#cmakedefine HAVE_MEMRCHR
#cmakedefine HAVE_BASENAME

#cmakedefine HAVE_NCURSES
#cmakedefine HAVE_GTK
#cmakedefine HAVE_GTK3
#cmakedefine HAVE_GTK3COMPAT

#cmakedefine HAVE_UTF8
#cmakedefine HAVE_PLUGINS
#cmakedefine WITH_IPV6
#cmakedefine HAVE_GEOIP
#cmakedefine HAVE_EC_LUA
#cmakedefine HAVE_CURL

#cmakedefine INSTALL_PREFIX         "@INSTALL_PREFIX@"
#cmakedefine INSTALL_SYSCONFDIR     "@INSTALL_SYSCONFDIR@"
#cmakedefine INSTALL_LIBDIR         "@INSTALL_LIBDIR@"
#cmakedefine INSTALL_DATADIR        "@INSTALL_DATADIR@"
#cmakedefine INSTALL_EXECPREFIX     "@INSTALL_EXECPREFIX@"
#cmakedefine INSTALL_BINDIR         "@INSTALL_BINDIR@"

#cmakedefine ICON_DIR               "@ICON_DIR@"
#cmakedefine MAN_INSTALLDIR         "@MAN_INSTALLDIR@"

#cmakedefine JUST_LIBRARY

#cmakedefine LIBNET_VERSION         "@LIBNET_VERSION@"
#cmakedefine LIBNET_VERSION_MAJOR   @LIBNET_VERSION_MAJOR@
#cmakedefine LIBNET_VERSION_MINOR   @LIBNET_VERSION_MINOR@
#endif
