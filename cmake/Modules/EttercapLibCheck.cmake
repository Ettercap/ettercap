## The easy part

set(EC_LIBS)
set(EC_INCLUDE)

set(EF_LIBS)
set(EL_LIBS)

# Generic target that will build all enabled bundled libs.
add_custom_target(bundled)

if(ENABLE_CURSES)
    set(CURSES_NEED_NCURSES TRUE)
    find_package(Curses REQUIRED)
    set(HAVE_NCURSES 1)
    set(EC_LIBS ${EC_LIBS} ${CURSES_LIBRARIES})
    set(EC_LIBS ${EC_LIBS} ${CURSES_NCURSES_LIBRARY})
    set(EC_LIBS ${EC_LIBS} ${CURSES_FORM_LIBRARY})
    set(EC_INCLUDE ${EC_INCLUDE} ${CURSES_INCLUDE_DIR})

    find_library(FOUND_PANEL panel)
    find_library(FOUND_MENU menu)

    if(FOUND_PANEL)
         set(EC_LIBS ${EC_LIBS} ${FOUND_PANEL})
    endif(FOUND_PANEL)

    if(FOUND_MENU)
         set(EC_LIBS ${EC_LIBS} ${FOUND_MENU})
    endif(FOUND_MENU)
endif(ENABLE_CURSES)

if(ENABLE_GTK)
    find_package(GTK2 2.10 REQUIRED gtk)
    set(HAVE_GTK 1)
    set(EC_LIBS ${EC_LIBS} ${GTK2_LIBRARIES})
    set(EC_INCLUDE ${EC_INCLUDE} ${GTK2_INCLUDE_DIRS})
    include_directories(${GTK2_INCLUDE_DIRS})

    if(OS_DARWIN) 
	find_library(FOUND_GTHREAD gthread-2.0)
    	if(FOUND_GTHREAD)
		set(EC_LIBS ${EC_LIBS} ${FOUND_GTHREAD})
    	endif(FOUND_GTHREAD)
    else(OS_DARWIN)
        set(EC_LIBS ${EC_LIBS} gthread-2.0)
    endif(OS_DARWIN)
endif(ENABLE_GTK)

if(ENABLE_SSL)
    find_package(OpenSSL REQUIRED)
    set(HAVE_OPENSSL 1)
    set(EC_LIBS ${EC_LIBS} ${OPENSSL_LIBRARIES})
    set(EC_INCLUDE ${EC_INCLUDE} ${OPENSSL_INCLUDE_DIR})
else(ENABLE_SSL)
    set(HAVE_OPENSSL 0)
endif(ENABLE_SSL)

find_package(ZLIB REQUIRED)
set(EC_LIBS ${EC_LIBS} ${ZLIB_LIBRARIES})
set(EC_INCLUDE ${EC_INCLUDE} ${ZLIB_INCLUDE_DIRS})
set(EL_LIBS ${EL_LIBS} ${ZLIB_LIBRARIES})

set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
    set(EC_LIBS ${EC_LIBS} ${CMAKE_THREAD_LIBS_INIT})
    set(EF_LIBS ${EF_LIBS} ${CMAKE_THREAD_LIBS_INIT})
    set(EL_LIBS ${EL_LIBS} ${CMAKE_THREAD_LIBS_INIT})
else(CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "pthreads not found")
endif(CMAKE_USE_PTHREADS_INIT)


## Thats all with packages, now we are on our own :(

include(CheckFunctionExists)
include(CheckIncludeFile)

# Iconv
CHECK_FUNCTION_EXISTS(iconv HAVE_UTF8)
if(NOT HAVE_UTF8)
    find_library(HAVE_ICONV iconv)
    if(HAVE_ICONV)
        set(HAVE_UTF8 1)
        set(EC_LIBS ${EC_LIBS} ${HAVE_ICONV})
        set(EL_LIBS ${EL_LIBS} ${HAVE_ICONV})
    endif(HAVE_ICONV)
endif(NOT HAVE_UTF8)

# LTDL
if(ENABLE_PLUGINS)
#    find_library(HAVE_LTDL ltdl)
#    if(HAVE_LTDL)
#        set(HAVE_PLUGINS 1)
#        set(EC_LIBS ${EC_LIBS} ${HAVE_LTDL})
#    endif(HAVE_LTDL)
    
    CHECK_FUNCTION_EXISTS(dlopen HAVE_DLOPEN)
    if(HAVE_DLOPEN)
        set(HAVE_PLUGINS 1)
    else(HAVE_DLOPEN)
        find_library(HAVE_DL dl)
        if(HAVE_DL)
            set(HAVE_PLUGINS 1)
            set(EC_LIBS ${EC_LIBS} ${HAVE_DL})
        endif(HAVE_DL)
    endif(HAVE_DLOPEN)
endif(ENABLE_PLUGINS)

if(HAVE_PLUGINS)
    # Fake target for curl
    ADD_CUSTOM_TARGET(curl)

    # sslstrip has a requirement for libcurl >= 7.26.0
    if(SYSTEM_CURL)
      find_package(CURL 7.26.0)

      if(NOT CURL_FOUND)
        message(STATUS "Couldn't find a suitable system-provided version of Curl")
      endif(NOT CURL_FOUND)
    endif(SYSTEM_CURL)

    if(BUNDLED_CURL AND (NOT CURL_FOUND))
      message(STATUS "Using bundled version of Curl")
      add_subdirectory(bundled_deps/curl EXCLUDE_FROM_ALL)
      add_dependencies(curl bundled_curl)
      add_dependencies(bundled bundled_curl)
    endif(BUNDLED_CURL AND (NOT CURL_FOUND))

    # Still haven't found curl? Bail!
    if(NOT CURL_FOUND)
      message(FATAL_ERROR "Could not find Curl!")
    endif(NOT CURL_FOUND)

endif(HAVE_PLUGINS)

CHECK_FUNCTION_EXISTS(poll HAVE_POLL)
CHECK_FUNCTION_EXISTS(strtok_r HAVE_STRTOK_R)
CHECK_FUNCTION_EXISTS(select HAVE_SELECT)
CHECK_FUNCTION_EXISTS(scandir HAVE_SCANDIR)

CHECK_FUNCTION_EXISTS(strlcat HAVE_STRLCAT)
CHECK_FUNCTION_EXISTS(strlcpy HAVE_STRLCPY)
CHECK_FUNCTION_EXISTS(strsep HAVE_STRSEP)
CHECK_FUNCTION_EXISTS(strcasestr HAVE_STRCASESTR)
CHECK_FUNCTION_EXISTS(memmem HAVE_MEMMEM)
CHECK_FUNCTION_EXISTS(basename HAVE_BASENAME)
CHECK_FUNCTION_EXISTS(strndup HAVE_STRNDUP)

find_library(HAVE_PCAP pcap)
if(HAVE_PCAP)
    set(EC_LIBS ${EC_LIBS} ${HAVE_PCAP})
else(HAVE_PCAP)
    message(FATAL_ERROR "libpcap not found!")
endif(HAVE_PCAP)

# begin LIBNET 

# This is a fake target that ettercap is dependant upon. If we end up using 
# a bundled version of libnet, we make this 'libnet' target dependant on it.
# That way, everything gets built in the proper order!
ADD_CUSTOM_TARGET(libnet)

if(SYSTEM_LIBNET)
  if(ENABLE_IPV6)
    message(STATUS "IPV6 support requested. Will look for libnet >= 1.1.5.")
    find_package(LIBNET "1.1.5")
  else(ENABLE_IPV6)
    find_package(LIBNET)
  endif(ENABLE_IPV6)

  if(NOT LIBNET_FOUND)
    message(STATUS "Couldn't find a suitable system-provided version of LIBNET")
  endif(NOT LIBNET_FOUND)
endif(SYSTEM_LIBNET)

# Only go into bundled stuff if it's enabled and we haven't found it already.
if(BUNDLED_LIBNET AND (NOT LIBNET_FOUND))
  message(STATUS "Using bundled version of LIBNET")
  add_subdirectory(bundled_deps/libnet EXCLUDE_FROM_ALL)
  add_dependencies(libnet bundled_libnet)
  add_dependencies(bundled bundled_libnet)
endif(BUNDLED_LIBNET AND (NOT LIBNET_FOUND))

# Still haven't found libnet? Bail!
if(NOT LIBNET_FOUND)
  message(FATAL_ERROR "Could not find LIBNET!")
endif(NOT LIBNET_FOUND)

include_directories(${LIBNET_INCLUDE_DIR})
set(EC_LIBS ${EC_LIBS} ${LIBNET_LIBRARY})

# end LIBNET 

find_library(HAVE_RESOLV resolv)
if(HAVE_RESOLV)
	set(EC_LIBS ${EC_LIBS} ${HAVE_RESOLV})
	set(HAVE_DN_EXPAND 1 CACHE PATH "Found dn_expand")
endif(HAVE_RESOLV)

find_package(PCRE)
if(PCRE_LIBRARY)
    set(HAVE_PCRE 1)
    include_directories(${PCRE_INCLUDE_DIR})
    set(EC_LIBS ${EC_LIBS} ${PCRE_LIBRARY})
    set(EF_LIBS ${EF_LIBS} ${PCRE_LIBRARY})
endif(PCRE_LIBRARY)
