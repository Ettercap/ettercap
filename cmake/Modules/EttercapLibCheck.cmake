## The easy part

set(EC_LIBS)
set(EC_INTERFACES_LIBS)
set(EC_INCLUDE)

# Generic target that will build all enabled bundled libs.
add_custom_target(bundled)

if(ENABLE_CURSES)
    set(CURSES_NEED_NCURSES TRUE)
    find_package(Curses REQUIRED)
    set(HAVE_NCURSES 1)
    set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} ${CURSES_LIBRARIES}
          ${CURSES_NCURSES_LIBRARY} ${CURSES_FORM_LIBRARY})
    set(EC_INCLUDE ${EC_INCLUDE} ${CURSES_INCLUDE_DIR} ${CURSES_INCLUDE_DIR}/ncurses)

    find_library(FOUND_PANEL panel)
    find_library(FOUND_MENU menu)

    if(FOUND_PANEL)
        set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} ${FOUND_PANEL})
    endif()

    if(FOUND_MENU)
        set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} ${FOUND_MENU})
    endif()
endif()


if(ENABLE_GTK)
    set(VALID_GTK_TYPES GTK2 GTK3)
    if(NOT DEFINED GTK_BUILD_TYPE)
        message(STATUS "No GTK_BUILD_TYPE defined, default is GTK3")
        set(GTK_BUILD_TYPE GTK3 CACHE STRING
        "Choose the type of gtk build, options are: ${VALID_GTK_TYPES}." FORCE)
    else()
        set(GTK_BUILD_TYPE ${GTK_BUILD_TYPE} CACHE STRING
        "Choose the type of gtk build, options are: ${VALID_GTK_TYPES}." FORCE)
    endif()
    list(FIND VALID_GTK_TYPES ${GTK_BUILD_TYPE} contains_valid)
    if(contains_valid EQUAL -1)
        message(FATAL_ERROR "Unknown GTK_BUILD_TYPE: '${GTK_BUILD_TYPE}'. Valid options are: ${VALID_GTK_TYPES}")
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
Please install it, or build against GTK1")
            endif()
        endif()
        set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} ${GTK3_LIBRARIES})
        set(EC_INCLUDE ${EC_INCLUDE} ${GTK3_INCLUDE_DIRS})
        include_directories(${GTK3_INCLUDE_DIRS})
    endif()
    if(GTK_BUILD_TYPE STREQUAL GTK2)
        find_package(GTK2 2.10 REQUIRED)
        if(NOT GTK2_FOUND)
            message(FATAL_ERROR "You choose to build against GTK2, please install it, or build against GTK3")
        else()
            message(DEPRECIATION "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            message(DEPRECIATION "  !  GTK2 phase-out started  !")
            message(DEPRECIATION "  !!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            message(DEPRECIATION "  Please consider building against GTK3.")
            message(DEPRECIATION "  GTK2 support will be dropped in future releases.")
        endif()
        set(HAVE_GTK 1)
        set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} ${GTK2_LIBRARIES})
        set(EC_INCLUDE ${EC_INCLUDE} ${GTK2_INCLUDE_DIRS})
        include_directories(${GTK2_INCLUDE_DIRS})
    endif()
    if(OS_DARWIN OR OS_BSD)
        find_library(FOUND_GTHREAD gthread-2.0)
        if(FOUND_GTHREAD)
            set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} ${FOUND_GTHREAD})
        endif()
    else()
        set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} gthread-2.0)
    endif()
endif()

find_package(OpenSSL REQUIRED)
set(EC_LIBS ${EC_LIBS} ${OPENSSL_LIBRARIES})
set(EC_INCLUDE ${EC_INCLUDE} ${OPENSSL_INCLUDE_DIR})

find_package(ZLIB REQUIRED)
set(EC_LIBS ${EC_LIBS} ${ZLIB_LIBRARIES})
set(EC_INCLUDE ${EC_INCLUDE} ${ZLIB_INCLUDE_DIRS})

set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads REQUIRED)
if(CMAKE_USE_PTHREADS_INIT)
    set(EC_LIBS ${EC_LIBS} ${CMAKE_THREAD_LIBS_INIT})
else()
    message(FATAL_ERROR "pthreads not found")
endif()


## Thats all with packages, now we are on our own :(

include(CheckFunctionExists)
include(CheckLibraryExists)
include(CheckIncludeFile)

# Iconv
find_library(HAVE_ICONV iconv)
check_function_exists(iconv HAVE_UTF8)
if(HAVE_ICONV)
    # Seem that we have a dedicated iconv library not built in libc (e.g. FreeBSD)
    set(HAVE_UTF8 1)
    set(EC_LIBS ${EC_LIBS} ${HAVE_ICONV})
else()
    if(HAVE_UTF8)
    # iconv built in libc
    else()
      message(FATAL_ERROR "iconv not found")
    endif()
endif()



# LTDL
if(ENABLE_PLUGINS)
    if(CMAKE_DL_LIBS)
        # dedicated libdl library
        set(HAVE_PLUGINS 1)
        set(EC_LIBS ${EC_LIBS} ${CMAKE_DL_LIBS})
    else()
        # included in libc
        check_function_exists(dlopen HAVE_DLOPEN)
        if(HAVE_DLOPEN)
            set(HAVE_PLUGINS 1)
        endif()
    endif()
endif()

if(HAVE_PLUGINS)
    # Fake target for curl
    add_custom_target(curl)

    # sslstrip has a requirement for libcurl >= 7.26.0
    if(SYSTEM_CURL)
        message(STATUS "CURL support requested. Will look for curl >= 7.26.0")
        find_package(CURL 7.26.0)

        if(NOT CURL_FOUND)
            message(STATUS "Couldn't find a suitable system-provided version of Curl")
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

check_function_exists(poll HAVE_POLL)
check_function_exists(strtok_r HAVE_STRTOK_R)
check_function_exists(select HAVE_SELECT)
check_function_exists(scandir HAVE_SCANDIR)

check_function_exists(strlcat HAVE_STRLCAT_FUNCTION)
check_function_exists(strlcpy HAVE_STRLCPY_FUNCTION)

if(NOT HAVE_STRLCAT_FUNCTION OR NOT HAVE_STRLCPY_FUNCTION)
    check_library_exists(bsd strlcat "bsd/string.h" HAVE_STRLCAT)
    check_library_exists(bsd strlcpy "bsd/string.h" HAVE_STRLCPY)
    if(HAVE_STRLCAT OR HAVE_STRLCPY)
        set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} bsd)
    endif()
endif()

check_function_exists(strsep HAVE_STRSEP)
check_function_exists(strcasestr HAVE_STRCASESTR)
check_function_exists(memmem HAVE_MEMMEM)
check_function_exists(memrchr HAVE_MEMRCHR)
check_function_exists(basename HAVE_BASENAME)
check_function_exists(strndup HAVE_STRNDUP)

find_library(HAVE_PCAP pcap)
if(HAVE_PCAP)
    set(EC_INTERFACES_LIBS ${EC_INTERFACES_LIBS} ${HAVE_PCAP})
else()
    message(FATAL_ERROR "libpcap not found!")
endif()

if(ENABLE_GEOIP)
    message(STATUS "GeoIP support requested. Will look for the legacy GeoIP C library")
    find_package(GEOIP)
        if(GEOIP_FOUND)
            set(HAVE_GEOIP 1)
            set(EC_LIBS ${EC_LIBS} ${GEOIP_LIBRARIES})
        else()
            message(FATAL_ERROR "GeoIP not found!")
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
    else()
        find_package(LIBNET)
    endif()

    if(NOT LIBNET_FOUND)
        message(STATUS "Couldn't find a suitable system-provided version of LIBNET")
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

include_directories(${LIBNET_INCLUDE_DIR})
set(EC_LIBS ${EC_LIBS} ${LIBNET_LIBRARY})

# end LIBNET

find_library(HAVE_RESOLV resolv)
if(HAVE_RESOLV)
    set(EC_LIBS ${EC_LIBS} ${HAVE_RESOLV})
    set(HAVE_DN_EXPAND 1 CACHE PATH "Found dn_expand")
else()
    if(OS_BSD)
        # FreeBSD has dn_expand built in libc
        check_function_exists(dn_expand HAVE_DN_EXPAND)
    endif()
endif()

find_package(PCRE)
if(PCRE_LIBRARY)
    set(HAVE_PCRE 1)
    include_directories(${PCRE_INCLUDE_DIR})
    set(EC_LIBS ${EC_LIBS} ${PCRE_LIBRARY})
endif()

if(ENABLE_TESTS)
    if(SYSTEM_LIBCHECK)
        find_package(LIBCHECK)
    endif()
    if(BUNDLED_LIBCHECK AND (NOT LIBCHECK_FOUND))
        add_subdirectory(bundled_deps/check) # EXCLUDE_FROM_ALL)
    else()
        find_library(LIB_RT rt)
        if(NOT OS_DARWIN AND (NOT LIB_RT))
            message(FATAL_ERROR "Could not find librt, which is required for linking tests.")
        endif()
    endif()
    if(NOT LIBCHECK_FOUND)
        message(FATAL_ERROR "Could not find LIBCHECK!")
    endif()
endif()
