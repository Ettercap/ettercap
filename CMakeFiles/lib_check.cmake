## The easy part

set(EC_LIBS)
set(EC_INCLUDE)

set(EF_LIBS)
set(EL_LIBS)

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
    set(EC_INCLUDE ${EC_INCLUDE} ${OPENSSL_INCLUDEDIRS})
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
    # sslstrip has a requirement for libcurl >= 7.26.0
    find_package(CURL 7.26.0 REQUIRED)
    include_directories(${CURL_INCLUDE_DIR})
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

find_library(HAVE_PCAP pcap)
if(HAVE_PCAP)
    set(EC_LIBS ${EC_LIBS} ${HAVE_PCAP})
else(HAVE_PCAP)
    message(FATAL_ERROR "libpcap not found!")
endif(HAVE_PCAP)

if(ENABLE_IPV6)
	set(LIBNET_REQUIRED_VERSION "1.1.5")
endif(ENABLE_IPV6)

find_package(LIBNET ${LIBNET_REQUIRED_VERSION} REQUIRED)
include_directories(${LIBNET_INCLUDE_DIR})
set(EC_LIBS ${EC_LIBS} ${LIBNET_LIBRARY})

find_library(HAVE_RESOLV resolv)
if(HAVE_RESOLV)
	set(EC_LIBS ${EC_LIBS} ${HAVE_RESOLV})
	set(HAVE_DN_EXPAND 1 CACHE PATH "Found dn_expand")
endif(HAVE_RESOLV)

find_library(HAVE_PCRE pcre)
if(HAVE_PCRE)
    set(EC_LIBS ${EC_LIBS} ${HAVE_PCRE})
    set(EF_LIBS ${EF_LIBS} ${HAVE_PCRE})
endif(HAVE_PCRE)
