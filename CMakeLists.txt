cmake_minimum_required(VERSION 2.8)
project(ettercap C)

set(VERSION "0.8.0")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")
include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build. Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

option(ENABLE_CURSES "Enable curses interface" ON)
option(ENABLE_GTK "Enable GTK interface" ON)
option(ENABLE_SSL "Enable SSL support" ON)
option(ENABLE_PLUGINS "Enable plugins support" ON)
option(ENABLE_IPV6 "Enable IPv6 support" OFF)
option(ENABLE_LUA "Enable LUA support (EXPERIMENTAL)" OFF)
option(ENABLE_PDF_DOCS "Enable PDF document generation" OFF)
option(ENABLE_TESTS "Enable Unit Tests" OFF)
option(LIBRARY_BUILD "Build for libettercap only" OFF)
option(INSTALL_DESKTOP "Install ettercap desktop files" ON)


SET(VALID_BUILD_TYPES Debug Release)

if(NOT CMAKE_BUILD_TYPE)
  # Default to using "Release" as our build type.
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING 
    "Choose the type of build, options are: ${VALID_BUILD_TYPES}." FORCE)
endif()
LIST(FIND VALID_BUILD_TYPES ${CMAKE_BUILD_TYPE} contains_valid)
if(contains_valid EQUAL -1)
  message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: '${CMAKE_BUILD_TYPE}'. Valid options are: ${VALID_BUILD_TYPES}") 
endif()
UNSET(contains_valid)

# Ensure that, when we link to stuff outside of our build path, we include the
# library dir path in our RPATH.
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

include(CMakeDependentOption)

# If SYSTEM_LIBS is set to off, then all SYSTEM_* options will be
# set to off.
option(SYSTEM_LIBS "Search for a system-provided libraries. This is only used for libraries that we happen to also bundle. Disabling this implies that we would only use bundled libraries." ON)

# If BUNDLED_LIBS is set to off, then all BUNDLED_* options will be
# set to off.
option(BUNDLED_LIBS
  "Use bundled libraries if system provided versions are not found (or disabled)" ON)

CMAKE_DEPENDENT_OPTION(SYSTEM_CURL 
  "Search for a system-provided version of Curl" ON
  SYSTEM_LIBS OFF)

CMAKE_DEPENDENT_OPTION(BUNDLED_CURL 
  "Use bundled version of Curl if system-provided version is not found (or disabled)" ON
  BUNDLED_LIBS OFF)

CMAKE_DEPENDENT_OPTION(SYSTEM_LIBNET 
  "Search for a system-provided version of LIBNET" ON
  SYSTEM_LIBS OFF)

CMAKE_DEPENDENT_OPTION(BUNDLED_LIBNET 
  "Use bundled version of LIBNET if system-provided version is not found (or disabled)" ON
  BUNDLED_LIBS OFF)

CMAKE_DEPENDENT_OPTION(SYSTEM_LUAJIT
  "Search for a system-provided version of LUAJIT" ON
  "SYSTEM_LIBS;ENABLE_LUA" OFF)

CMAKE_DEPENDENT_OPTION(BUNDLED_LUAJIT
  "Use bundled version of LUAJIT if system-provided version is not found (or disabled)" ON
  "BUNDLED_LIBS;ENABLE_LUA" OFF)

set(SPECIAL_LIB_DIR "" CACHE PATH "Special (non-traditional) root directory where headers/libraries are installed")

include(CheckVariableInHeaders)
include(EttercapOSTest)

#Check and see if we're running Darwin, specify the CMAKE_LIBARY_PATH to do so
if(OS_DARWIN)
	set(CMAKE_SYSTEM_NAME Darwin)
	set(CMAKE_LIBRARY_PATH ${SPECIAL_LIB_DIR}/lib ${CMAKE_LIBRARY_PATH})
	set(CMAKE_INCLUDE_PATH ${SPECIAL_LIB_DIR}/include ${CMAKE_INCLUDE_PATH})
else(OS_DARWIN)
	set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /usr/lib64 /usr/lib32)
endif(OS_DARWIN)

if (LIBRARY_BUILD)
	set(ENABLE_GTK OFF)
	set(ENABLE_CURSES OFF)
	set(JUST_LIBRARY 1)
endif(LIBRARY_BUILD)

include(EttercapHeadersCheck)
include(EttercapLibCheck)
include(EttercapVariableCheck)

set(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX} CACHE PATH "Installation prefix")
set(INSTALL_SYSCONFDIR /etc CACHE PATH "System configuration directory")
set(INSTALL_LIBDIR ${INSTALL_PREFIX}/lib${LIB_SUFFIX} CACHE PATH "Library installation directory")
set(INSTALL_DATADIR ${INSTALL_PREFIX}/share CACHE PATH "Data installation directory")
set(INSTALL_EXECPREFIX ${INSTALL_PREFIX} CACHE PATH "")
set(INSTALL_BINDIR ${INSTALL_PREFIX}/bin CACHE PATH "Binary files installation directory")
set(POLKIT_DIR ${INSTALL_PREFIX}/share/polkit-1/actions/ CACHE PATH "Binary files installation directory")
set(PKEXEC_INSTALL_WRAPPER org.pkexec.ettercap CACHE PATH "Name of the pkexec action file")
set(DESKTOP_DIR ${INSTALL_PREFIX}/share/applications/ CACHE PATH "Binary files installation directory")
set(ICON_DIR ${INSTALL_PREFIX}/share/pixmaps CACHE PATH "Binary files installation directory")
set(MAN_INSTALLDIR ${INSTALL_PREFIX}/share/man CACHE PATH "Path for manual pages") 

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

if(ENABLE_LUA)
  include(EttercapLuajit)
  set(HAVE_EC_LUA 1)
endif(ENABLE_LUA)

set(EC_INCLUDE_PATH ${CMAKE_CURRENT_BINARY_DIR}/include ${CMAKE_SOURCE_DIR}/include)
include_directories(${EC_INCLUDE_PATH})

add_subdirectory(src)
add_subdirectory(desktop)

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
configure_file(include/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/include/config.h)

if(ENABLE_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif(ENABLE_TESTS)

# Add a target that will ensure that the build directory is properly cleaned.
add_custom_target(clean-all
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/cmake/Scripts/clean-all.cmake
)

# If we notice that this isn't the first time they've run 
if(NOT ("${CMAKE_CACHEFILE_DIR}" STREQUAL ""))
  message("")
  message("HAVING TROUBLE BUILDING ETTERCAP? ")
  message("")
  message("  1. Install any missing dependencies")
  message("  2. run 'make clean-all'")
  message("  3. run 'cmake ${CMAKE_SOURCE_DIR}'")
  message("")
endif(NOT ("${CMAKE_CACHEFILE_DIR}" STREQUAL ""))

