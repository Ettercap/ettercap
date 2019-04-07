## The "easy" part

if(BUNDLED_LIBS)
  # Generic target that will build all enabled bundled libs.
  add_custom_target(bundled)
endif()

if(ENABLE_CURSES)
  set(CURSES_NEED_NCURSES TRUE)
  find_package(CURSES REQUIRED)
  set(HAVE_NCURSES 1)
  list(APPEND EC_UI_LIBS ${CURSES_LIBRARIES})
  list(APPEND EC_UI_INCLUDE ${CURSES_INCLUDE_DIRS})

  if(CURSES_HAVE_NCURSES_NCURSES_H)
    list(APPEND EC_UI_INCLUDE ${CURSES_INCLUDE_DIRS}/ncurses)
  endif()

  if(CURSES_NEED_WIDE)
    set(CURSES_WIDE w)
  endif()

  find_library(CURSES_PANEL_LIBRARY panel${CURSES_WIDE}
    DOC "Panel stack extension for ncurses"
    HINTS "${_cursesLibDir}" # Don't Try This at Home.
  )
  find_library(CURSES_MENU_LIBRARY menu${CURSES_WIDE}
    DOC "ncurses extension for programming menus"
    HINTS "${_cursesLibDir}" # Don't Try This at Home.
  )

  if(CURSES_PANEL_LIBRARY AND CURSES_MENU_LIBRARY)
    list(APPEND EC_UI_LIBS ${CURSES_PANEL_LIBRARY} ${CURSES_MENU_LIBRARY})
  elseif(NOT CURSES_PANEL_LIBRARY)
    message(FATAL_ERROR "libpanel${CURSES_WIDE} not found.")
  else()
    message(FATAL_ERROR "libmenu${CURSES_WIDE} not found.")
  endif()

endif()

if(ENABLE_GTK)
  set(VALID_GTK_TYPES GTK2 GTK3)
  if(NOT DEFINED GTK_BUILD_TYPE)
    message(STATUS "No GTK_BUILD_TYPE defined, default is GTK3")
    set(GTK_BUILD_TYPE GTK3 CACHE STRING
      "Choose the type of GTK build, options are: ${VALID_GTK_TYPES}." FORCE)
  else()
    set(GTK_BUILD_TYPE ${GTK_BUILD_TYPE} CACHE STRING
      "Choose the type of GTK build, options are: ${VALID_GTK_TYPES}." FORCE)
  endif()
  list(FIND VALID_GTK_TYPES ${GTK_BUILD_TYPE} contains_valid)
  if(contains_valid EQUAL -1)
    message(FATAL_ERROR "Unknown GTK_BUILD_TYPE: '${GTK_BUILD_TYPE}'. \
      Valid options are: ${VALID_GTK_TYPES}"
    )
  endif()
  unset(contains_valid)
  if(GTK_BUILD_TYPE STREQUAL GTK3)
    set(GTK3_FIND_VERSION 1)
    find_package(GTK3 3.12.0)
    if(GTK3_FOUND)
      set(HAVE_GTK3 1)
    else()
      # give it another try but only in GTK3 compatibility mode
      find_package(GTK3 REQUIRED)
      if(GTK3_FOUND)
        message("\n\
Your version of GTK3 (${GTK3_VERSION}) is not \
sufficient for full GTK3 support.\n\
Full support requires >= 3.12.\n\
Building in GTK3 compatibility mode.\n")
        set(HAVE_GTK3COMPAT 1)
      else()
        message(FATAL_ERROR
"You choose to build against GTK3.\
Please install it, or build against GTK2")
      endif()
    endif()
    list(APPEND EC_UI_LIBS ${GTK3_LIBRARIES})
    list(APPEND EC_UI_INCLUDE ${GTK3_INCLUDE_DIRS})
  endif()
  if(GTK_BUILD_TYPE STREQUAL GTK2)
    if(OS_WINDOWS)
      set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH 1)
      find_package(PkgConfig REQUIRED QUIET)
      pkg_check_modules(GTK2 REQUIRED gtk+-2.0>=2.10)
    else()
      find_package(GTK2 2.10 REQUIRED)
    endif()
    set(HAVE_GTK 1)
    list(APPEND EC_UI_LIBS ${GTK2_LIBRARIES})
    list(APPEND EC_UI_INCLUDE ${GTK2_INCLUDE_DIRS})
  endif()
  if(OS_DARWIN OR OS_BSD)
    find_library(GTHREAD_LIBRARY gthread-2.0)
    if(GTHREAD_LIBRARY)
      list(APPEND EC_UI_LIBS ${GTHREAD_LIBRARY})
    endif()
  else()
    list(APPEND EC_UI_LIBS gthread-2.0)
  endif()
endif()

find_package(OpenSSL REQUIRED)
list(APPEND EC_LIBS ${OPENSSL_LIBRARIES})
list(APPEND EC_INCLUDE ${OPENSSL_INCLUDE_DIR})

find_package(ZLIB REQUIRED)
list(APPEND EC_LIBS ${ZLIB_LIBRARIES})
list(APPEND EC_INCLUDE ${ZLIB_INCLUDE_DIRS})

set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
  list(APPEND EC_LIBS ${CMAKE_THREAD_LIBS_INIT})
else()
  if(OS_WINDOWS)
    # Try again but this time look for Pthreads-win32.
    find_package(PTHREADS-WIN32 REQUIRED)
    if(PTHREADS-WIN32_FOUND)
      list(APPEND EC_LIBS ${PTHREADS-WIN32_LIBRARY})
      list(APPEND EC_INCLUDE ${PTHREADS-WIN32_INCLUDE_DIR})
      list(APPEND EC_DEFINITIONS ${PTHREADS-WIN32_DEFINITIONS})
    else()
      message(FATAL_ERROR "Unable to find winpthreads or Pthreads-win32.")
    endif()
  else()
    message(FATAL_ERROR "Pthreads not found.")
  endif()
endif()

include(CheckFunctionExists)

# Find the iconv() POSIX.1 functions
find_library(ICONV_LIBRARIES NAMES iconv libiconv)
find_path(ICONV_INCLUDE_DIRS iconv.h)
if(ICONV_LIBRARIES AND ICONV_INCLUDE_DIRS)
  # Seem that we have a dedicated iconv library
  # not built in libc (e.g. FreeBSD)
  set(HAVE_UTF8 1)
  list(APPEND EC_LIBS ${ICONV_LIBRARIES})
  list(APPEND EC_INCLUDE ${ICONV_INCLUDE_DIRS})
else()
  # iconv built in libc
  check_function_exists(iconv HAVE_UTF8)
  if(NOT HAVE_UTF8)
    message(FATAL_ERROR "iconv not found")
  endif()
endif()

# LTDL
if(ENABLE_PLUGINS)
  if(OS_WINDOWS)
    set(HAVE_PLUGINS 1)
  elseif(CMAKE_DL_LIBS)
    # dedicated libdl library
    set(HAVE_PLUGINS 1)
    list(APPEND EC_LIBS ${CMAKE_DL_LIBS})
  else()
    # included in libc
    check_function_exists(dlopen HAVE_DLOPEN)
    if(HAVE_DLOPEN)
      set(HAVE_PLUGINS 1)
    endif()
  endif()
endif()

if(HAVE_PLUGINS)
  if(BUNDLED_LIBS)
    # Fake target for curl
    add_custom_target(curl)
  endif()

  # sslstrip has a requirement for libcurl >= 7.26.0
  if(SYSTEM_CURL)
    message(STATUS "CURL support requested. Will look for curl >= 7.26.0")
    find_package(CURL 7.26.0)

    if(NOT CURL_FOUND)
      message(STATUS "Couldn't find a suitable \
system-provided version of Curl")
    endif()
  endif()

  if(BUNDLED_CURL AND (NOT CURL_FOUND))
    message(STATUS "Using bundled version of Curl")
    add_subdirectory(bundled_deps/curl) # EXCLUDE_FROM_ALL)
    add_dependencies(curl bundled_curl)
    add_dependencies(bundled bundled_curl)
  endif()

  # Still haven't found curl? Bail!
  if(NOT CURL_FOUND)
    message(FATAL_ERROR "Could not find Curl!")
  endif()

endif()

find_library(PCAP_LIBRARIES NAMES pcap wpcap)
find_path(PCAP_INCLUDE_DIRS pcap.h)
if(PCAP_LIBRARIES AND PCAP_INCLUDE_DIRS)
  list(APPEND EC_LIBS ${PCAP_LIBRARIES})
  list(APPEND EC_INCLUDE ${PCAP_INCLUDE_DIRS})
elseif(NOT PCAP_LIBRARIES)
  message(FATAL_ERROR "libpcap not found!")
elseif(NOT PCAP_INCLUDE_DIRS)
  message(FATAL_ERROR "pcap.h not found!")
endif()

if(ENABLE_GEOIP)
  find_package(GEOIP 1.6.0 REQUIRED)
  if(GEOIP_FOUND)
    set(HAVE_GEOIP 1)
    list(APPEND EC_LIBS ${GEOIP_LIBRARIES})
    list(APPEND EC_INCLUDE ${GEOIP_INCLUDE_DIRS})
    list(APPEND EC_DEFINITIONS ${GEOIP_DEFINITIONS})
  endif()
endif()

# begin LIBNET

# This is a fake target that ettercap is dependant upon. If we end up using
# a bundled version of libnet, we make this 'libnet' target dependant on it.
# That way, everything gets built in the proper order!
add_custom_target(libnet)

if(SYSTEM_LIBNET)
  if(ENABLE_IPV6)
    message(STATUS "IPV6 support requested. Will look for libnet >= 1.1.5")
    find_package(LIBNET "1.1.5")

    if(LIBNET_FOUND)
      set(WITH_IPV6 TRUE)
    endif()
  else()
    find_package(LIBNET)
  endif()

  if(NOT LIBNET_FOUND)
    message(STATUS "Couldn't find a suitable system-provided \
version of LIBNET")
  endif()
endif()

# Only go into bundled stuff if it's enabled and we haven't found it already.
if(BUNDLED_LIBNET AND (NOT LIBNET_FOUND))
  message(STATUS "Using bundled version of LIBNET")
  add_subdirectory(bundled_deps/libnet) # EXCLUDE_FROM_ALL)
  add_dependencies(libnet bundled_libnet)
  add_dependencies(bundled bundled_libnet)
endif()

# Still haven't found libnet? Bail!
if(NOT LIBNET_FOUND)
  message(FATAL_ERROR "Could not find LIBNET!")
endif()

list(APPEND EC_INCLUDE ${LIBNET_INCLUDE_DIRS})
list(APPEND EC_LIBS ${LIBNET_LIBRARIES})
list(APPEND EC_DEFINITIONS ${LIBNET_DEFINITIONS})

# end LIBNET

find_library(HAVE_RESOLV resolv)
if(HAVE_RESOLV)
  list(APPEND EC_LIBS ${HAVE_RESOLV})
  set(HAVE_DN_EXPAND 1 CACHE PATH "Found dn_expand")
elseif(OS_BSD)
  # FreeBSD has dn_expand built in libc
  cmake_push_check_state(RESET)
  check_function_exists(dn_expand HAVE_DN_EXPAND)
  cmake_pop_check_state()
elseif(OS_WINDOWS)
  # Windows has dn_expand built in mswsock.
  # http://www.sockets.com/mswsock.htm
  # But we aren't using it (yet or never; I'm not sure, maybe it's a stub).
  # We have our own ec_win_dn_expand() that does the job for us.
  # So for now, the success of this test is only meant for
  # HAVE_DN_EXPAND to become True (if it isn't already via HAVE_RESOLV).
  cmake_push_check_state(RESET)
  # set(CMAKE_REQUIRED_QUIET 1)
  set(CMAKE_REQUIRED_LIBRARIES mswsock)
  check_function_exists(dn_expand HAVE_DN_EXPAND)
  cmake_pop_check_state()
else()
    message(FATAL_ERROR "Neither libresolv nor dn_expand() found.")
endif()

if(NOT OS_WINDOWS)
  find_package(PCRE)
else()
  find_package(PCRE 8.38 REQUIRED pcreposix)
endif()
if(PCRE_FOUND)
  set(HAVE_PCRE 1)
  list(APPEND EC_INCLUDE ${PCRE_INCLUDE_DIRS})
  list(APPEND EC_LIBS ${PCRE_LIBRARIES})
endif()

if(ENABLE_TESTS)
  if(SYSTEM_LIBCHECK)
    find_package(CHECK)
  endif()
  if(BUNDLED_LIBCHECK AND (NOT CHECK_FOUND))
    add_subdirectory(bundled_deps/check)
  endif()
endif()

if(ENABLE_LUA)
  add_custom_target(luajit)

  if(SYSTEM_LUAJIT)
    find_package(LUAJIT 2.0.0)

    if(NOT LUAJIT_FOUND)
      message(STATUS
"Couldn't find a suitable system-provided version of LuaJIT")
    endif()
  endif()

  # Only go into bundled stuff if it's enabled and we haven't found it already.
  if(BUNDLED_LUAJIT AND (NOT LUAJIT_FOUND))
    message(STATUS "Using bundled version of LUAJIT")
    add_subdirectory(bundled_deps/luajit EXCLUDE_FROM_ALL)
    add_dependencies(luajit bundled_luajit)
    add_dependencies(bundled bundled_luajit)
  endif()

  if(NOT LUAJIT_FOUND)
    message(FATAL_ERROR "Could not find LUAJIT!")
  endif()

  set(HAVE_EC_LUA 1)
endif()

# Clean up
list(REMOVE_DUPLICATES EC_INCLUDE)
list(REMOVE_DUPLICATES EC_UI_INCLUDE)
