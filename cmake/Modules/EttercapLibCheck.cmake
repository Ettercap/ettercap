## The easy part

set(EC_LIBS)
set(EC_LIBETTERCAP_LIBS)
set(EC_INCLUDE)

# Generic target that will build all enabled bundled libs.
add_custom_target(bundled)

if(ENABLE_CURSES)
    set(CURSES_NEED_NCURSES TRUE)
    find_package(Curses REQUIRED)
    set(HAVE_NCURSES 1)
    set(EC_LIBS ${EC_LIBS} ${CURSES_LIBRARIES})
    set(EC_LIBS ${EC_LIBS} ${CURSES_NCURSES_LIBRARY})
    set(EC_LIBS ${EC_LIBS} ${CURSES_FORM_LIBRARY})
    set(EC_INCLUDE ${EC_INCLUDE} ${CURSES_INCLUDE_DIR} ${CURSES_INCLUDE_DIR}/ncurses)

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
    SET(VALID_GTK_TYPES GTK2 GTK3)
    if(NOT DEFINED GTK_BUILD_TYPE)
        message(STATUS "No GTK_BUILD_TYPE defined, default is GTK2")
        set(GTK_BUILD_TYPE GTK2 CACHE STRING 
        "Choose the type of gtk build, options are: ${VALID_GTK_TYPES}." FORCE)
    endif(NOT DEFINED GTK_BUILD_TYPE)
    LIST(FIND VALID_GTK_TYPES ${GTK_BUILD_TYPE} contains_valid)
    if(contains_valid EQUAL -1)
        message(FATAL_ERROR "Unknown GTK_BUILD_TYPE: '${GTK_BUILD_TYPE}'. Valid options are: ${VALID_GTK_TYPES}")
    endif()
    UNSET(contains_valid)
    if(GTK_BUILD_TYPE STREQUAL GTK3)
        find_package(GTK3 REQUIRED)
        if(NOT GTK3_FOUND)
            message(FATAL_ERROR "You choose to build against GTK3, please install it, or build against GTK2")
        endif(NOT GTK3_FOUND)
        set(HAVE_GTK3 1)
        set(EC_LIBS ${EC_LIBS} ${GTK3_LIBRARIES})
        set(EC_INCLUDE ${EC_INCLUDE} ${GTK3_INCLUDE_DIRS})
        include_directories(${GTK3_INCLUDE_DIRS})
    endif(GTK_BUILD_TYPE STREQUAL GTK3)
    if(GTK_BUILD_TYPE STREQUAL GTK2)
        find_package(GTK2 2.10 REQUIRED)
        if(NOT GTK2_FOUND)
            message(FATAL_ERROR "You choose to build against GTK2, please install it, or build against GTK3")
        endif(NOT GTK2_FOUND)
        set(HAVE_GTK 1)
        set(EC_LIBS ${EC_LIBS} ${GTK2_LIBRARIES})
        set(EC_INCLUDE ${EC_INCLUDE} ${GTK2_INCLUDE_DIRS})
        include_directories(${GTK2_INCLUDE_DIRS})
    endif(GTK_BUILD_TYPE STREQUAL GTK2)
    if(OS_DARWIN OR OS_BSD)
        find_library(FOUND_GTHREAD gthread-2.0)
        if(FOUND_GTHREAD)
            set(EC_LIBS ${EC_LIBS} ${FOUND_GTHREAD})
        endif(FOUND_GTHREAD)
    else(OS_DARWIN OR OS_BSD)
        set(EC_LIBS ${EC_LIBS} gthread-2.0)
    endif(OS_DARWIN OR OS_BSD)
endif(ENABLE_GTK)

find_package(OpenSSL REQUIRED)
set(EC_LIBS ${EC_LIBS} ${OPENSSL_LIBRARIES})
set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${OPENSSL_LIBRARIES})
set(EC_INCLUDE ${EC_INCLUDE} ${OPENSSL_INCLUDE_DIR})

find_package(ZLIB REQUIRED)
set(EC_LIBS ${EC_LIBS} ${ZLIB_LIBRARIES})
set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${ZLIB_LIBRARIES})
set(EC_INCLUDE ${EC_INCLUDE} ${ZLIB_INCLUDE_DIRS})

set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
    set(EC_LIBS ${EC_LIBS} ${CMAKE_THREAD_LIBS_INIT})
    set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${CMAKE_THREAD_LIBS_INIT})
else(CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "pthreads not found")
endif(CMAKE_USE_PTHREADS_INIT)


## Thats all with packages, now we are on our own :(

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckIncludeFile)

# Iconv
FIND_LIBRARY(HAVE_ICONV iconv)
CHECK_FUNCTION_EXISTS(iconv HAVE_UTF8)
if(HAVE_ICONV)
    # Seem that we have a dedicated iconv library not built in libc (e.g. FreeBSD)
    set(HAVE_UTF8 1)
    set(EC_LIBS ${EC_LIBS} ${HAVE_ICONV})
    set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${HAVE_ICONV})
else(HAVE_ICONV)
    if(HAVE_UTF8)
       # iconv built in libc
    else(HAVE_UTF8)
       message(FATAL_ERROR "iconv not found")
    endif(HAVE_UTF8)
endif(HAVE_ICONV)



# LTDL
if(ENABLE_PLUGINS)
    if(CMAKE_DL_LIBS)
        # dedicated libdl library
        set(HAVE_PLUGINS 1)
        set(EC_LIBS ${EC_LIBS} ${CMAKE_DL_LIBS})
        set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${CMAKE_DL_LIBS})
    else(CMAKE_DL_LIBS)
        # included in libc
        CHECK_FUNCTION_EXISTS(dlopen HAVE_DLOPEN)
        if(HAVE_DLOPEN)
            set(HAVE_PLUGINS 1)
        endif(HAVE_DLOPEN)
    endif(CMAKE_DL_LIBS)
endif(ENABLE_PLUGINS)

if(HAVE_PLUGINS)
    # Fake target for curl
    ADD_CUSTOM_TARGET(curl)

    # sslstrip has a requirement for libcurl >= 7.26.0
    if(SYSTEM_CURL)
        message(STATUS "CURL support requested. Will look for curl >= 7.26.0")
        find_package(CURL 7.26.0)

        if(NOT CURL_FOUND)
            message(STATUS "Couldn't find a suitable system-provided version of Curl")
        endif(NOT CURL_FOUND)
    endif(SYSTEM_CURL)

    if(BUNDLED_CURL AND (NOT CURL_FOUND))
        message(STATUS "Using bundled version of Curl")
        add_subdirectory(bundled_deps/curl) # EXCLUDE_FROM_ALL)
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

CHECK_FUNCTION_EXISTS(strlcat HAVE_STRLCAT_FUNCTION)
CHECK_FUNCTION_EXISTS(strlcpy HAVE_STRLCPY_FUNCTION)

if(NOT HAVE_STRLCAT_FUNCTION OR NOT HAVE_STRLCPY_FUNCTION)
    CHECK_LIBRARY_EXISTS(bsd strlcat "bsd/string.h" HAVE_STRLCAT)
    CHECK_LIBRARY_EXISTS(bsd strlcpy "bsd/string.h" HAVE_STRLCPY)
    if(HAVE_STRLCAT OR HAVE_STRLCPY)
        set(EC_LIBS ${EC_LIBS} bsd)
        set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} bsd)
    endif(HAVE_STRLCAT OR HAVE_STRLCPY)
endif(NOT HAVE_STRLCAT_FUNCTION OR NOT HAVE_STRLCPY_FUNCTION)

CHECK_FUNCTION_EXISTS(strsep HAVE_STRSEP)
CHECK_FUNCTION_EXISTS(strcasestr HAVE_STRCASESTR)
CHECK_FUNCTION_EXISTS(memmem HAVE_MEMMEM)
CHECK_FUNCTION_EXISTS(basename HAVE_BASENAME)
CHECK_FUNCTION_EXISTS(strndup HAVE_STRNDUP)
CHECK_FUNCTION_EXISTS(inet_aton HAVE_INET_ATON)

find_library(HAVE_PCAP pcap)
if(HAVE_PCAP)
    set(EC_LIBS ${EC_LIBS} ${HAVE_PCAP})
    set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${HAVE_PCAP})
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
        message(STATUS "IPV6 support requested. Will look for libnet >= 1.1.5")
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
    add_subdirectory(bundled_deps/libnet) # EXCLUDE_FROM_ALL)
    add_dependencies(libnet bundled_libnet)
    add_dependencies(bundled bundled_libnet)
endif(BUNDLED_LIBNET AND (NOT LIBNET_FOUND))

# Still haven't found libnet? Bail!
if(NOT LIBNET_FOUND)
    message(FATAL_ERROR "Could not find LIBNET!")
endif(NOT LIBNET_FOUND)

include_directories(${LIBNET_INCLUDE_DIR})
set(EC_LIBS ${EC_LIBS} ${LIBNET_LIBRARY})
set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${LIBNET_LIBRARY})

# end LIBNET 

find_library(HAVE_RESOLV resolv)
if(HAVE_RESOLV)
    set(EC_LIBS ${EC_LIBS} ${HAVE_RESOLV})
    set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${HAVE_RESOLV})
    set(HAVE_DN_EXPAND 1 CACHE PATH "Found dn_expand")
else(HAVE_RESOLV)
    if(OS_BSD)
        # FreeBSD has dn_expand built in libc
        CHECK_FUNCTION_EXISTS(dn_expand HAVE_DN_EXPAND)
    endif(OS_BSD)
endif(HAVE_RESOLV)

find_package(PCRE)
if(PCRE_LIBRARY)
    set(HAVE_PCRE 1)
    include_directories(${PCRE_INCLUDE_DIR})
    set(EC_LIBS ${EC_LIBS} ${PCRE_LIBRARY})
    set(EC_LIBETTERCAP_LIBS ${EC_LIBETTERCAP_LIBS} ${PCRE_LIBRARY})
endif(PCRE_LIBRARY)

if(ENABLE_TESTS)
    if(SYSTEM_LIBCHECK)
        find_package(LIBCHECK)
    endif(SYSTEM_LIBCHECK)
    if(BUNDLED_LIBCHECK AND (NOT LIBCHECK_FOUND))
        add_subdirectory(bundled_deps/check) # EXCLUDE_FROM_ALL)
    else(BUNDLED_LIBCHECK AND (NOT LIBCHECK_FOUND))
        find_library(LIB_RT rt)
        if(NOT OS_DARWIN AND (NOT LIB_RT))
            message(FATAL_ERROR "Could not find librt, which is required for linking tests.")
        endif(NOT OS_DARWIN AND (NOT LIB_RT))
    endif(BUNDLED_LIBCHECK AND (NOT LIBCHECK_FOUND))
    if(NOT LIBCHECK_FOUND)
        message(FATAL_ERROR "Could not find LIBCHECK!")
    endif(NOT LIBCHECK_FOUND)
endif(ENABLE_TESTS)
