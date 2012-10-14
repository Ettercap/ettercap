cmake_minimum_required(VERSION 2.8)
project(ettercap C)

set(VERSION "0.7.5")

option(ENABLE_CURSES "Enable curses interface" ON)
option(ENABLE_GTK "Enable GTK interface" ON)
option(ENABLE_SSL "Enable SSL support" ON)
option(ENABLE_PLUGINS "Enable plugins support" ON)
option(ENABLE_IPV6 "Enable IPv6 support" OFF)
option(ENABLE_LUA "Enable LUA support" OFF)

set(MACPORTS_BASE_DIRECTORY "/opt/local" CACHE PATH "MacPorts installation base directory")
set(SPECIAL_LIB_DIR "" CACHE PATH "Special (non-traditional) directory where libraries are installed")

# Set the build type to Release, by default. Warn that the user should have 
# selected a build type
if("${CMAKE_BUILD_TYPE}" STREQUAL "") 
  message("Warning: CMAKE_BUILD_TYPE not specified. Defaulting to 'Release'")
  SET(CMAKE_BUILD_TYPE Release)
endif("${CMAKE_BUILD_TYPE}" STREQUAL "") 


include(CMakeModules/CheckVariableInHeaders.cmake)
include(CMakeFiles/os_test.cmake)

#Check and see if we're running Darwin, specify the CMAKE_LIBARY_PATH to do so
if(OS_DARWIN)
	set(CMAKE_SYSTEM_NAME Darwin)
	set(CMAKE_LIBRARY_PATH ${MACPORTS_BASE_DIRECTORY}/lib ${CMAKE_LIBRARY_PATH})
	set(CMAKE_INCLUDE_PATH ${MACPORTS_BASE_DIRECTORY}/include ${CMAKE_INCLUDE_PATH})
else(OS_DARWIN)
	set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /usr/lib64 /usr/lib32)
endif(OS_DARWIN)

include(CMakeFiles/headers_check.cmake)
include(CMakeFiles/lib_check.cmake)
if(ENABLE_LUA)
  include(CMakeFiles/luajit.cmake)
  set(HAVE_LUA 1)
endif(ENABLE_LUA)
include(CMakeFiles/variable_check.cmake)

set(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX} CACHE PATH "Installation prefix")
set(INSTALL_SYSCONFDIR /etc CACHE PATH "System configuration directory")
set(INSTALL_LIBDIR ${INSTALL_PREFIX}/lib${LIB_SUFFIX} CACHE PATH "Library installation directory")
set(INSTALL_DATADIR ${INSTALL_PREFIX}/share CACHE PATH "Data installation directory")
set(INSTALL_EXECPREFIX ${INSTALL_PREFIX} CACHE PATH "")
set(INSTALL_BINDIR ${INSTALL_PREFIX}/bin CACHE PATH "Binary files installation directory")
set(MAN_INSTALLDIR ${INSTALL_PREFIX}/share/man CACHE PATH "Path for manual pages") 

set(INSTALL_LUA_ROOT ${INSTALL_DATADIR}/lua CACHE PATH "Root installation directory for LUA-ettercap")
set(INSTALL_LUA_INIT ${INSTALL_LUA_ROOT}/init.lua CACHE FILEPATH "Initialization script for LUA-ettercap")
set(INSTALL_LUA_CORE ${INSTALL_LUA_ROOT}/core CACHE PATH "Core LUA-ettercap implementation lib installtion directory")
set(INSTALL_LUA_LIBS ${INSTALL_LUA_ROOT}/lib CACHE PATH "Auxillary LUA-ettercap lib installation directory")
set(INSTALL_LUA_SCRIPTS ${INSTALL_LUA_ROOT}/scripts CACHE PATH "LUA-ettercap scripts installation directory")

set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb3 -DDEBUG -Wall -Wno-pointer-sign -pg" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O2 -w" CACHE STRING "" FORCE)

if(OS_DARWIN)
set(CMAKE_EXE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl -pg" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
else(OS_DARWIN)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-export-dynamic" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl,-export-dynamic -pg" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-export-dynamic" CACHE STRING "" FORCE)
endif(OS_DARWIN)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_SOURCE_DIR}/CMakeModules)

set(EC_INCLUDE_PATH ${CMAKE_SOURCE_DIR}/include)
include_directories(${EC_INCLUDE_PATH})

add_subdirectory(src)

if(HAVE_PLUGINS)
    if(OS_MINGW)
        message("Sorry, plugins support on Windows is currently unavailable")
    else(OS_MINGW)
        add_subdirectory(plug-ins)
    endif(OS_MINGW)
endif(HAVE_PLUGINS)
add_subdirectory(utils)
add_subdirectory(share)
add_subdirectory(man)

if(ENABLE_IPV6)
    set(WITH_IPV6 TRUE)
endif(ENABLE_IPV6)

# This line should ALWAYS be after all options are defined
configure_file(include/config.h.cmake ${CMAKE_SOURCE_DIR}/include/config.h)

