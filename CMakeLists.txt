cmake_minimum_required(VERSION 2.8)
project(ettercap C)

set(VERSION "0.8.3")

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")
set(CMAKE_SCRIPT_PATH "${CMAKE_SOURCE_DIR}/cmake/Scripts")

include(MacroEnsureOutOfSourceBuild)
macro_ensure_out_of_source_build("${PROJECT_NAME} requires an out of source build.
Please create a separate build directory and run 'cmake /path/to/${PROJECT_NAME} [options]' there.")

option(ENABLE_CURSES "Enable curses interface" ON)
option(ENABLE_GTK "Enable GTK interface" ON)
option(ENABLE_PLUGINS "Enable plugins support" ON)
option(ENABLE_IPV6 "Enable IPv6 support" OFF)
option(ENABLE_LUA "Enable LUA support (EXPERIMENTAL)" OFF)
option(ENABLE_PDF_DOCS "Enable PDF document generation" OFF)
option(ENABLE_TESTS "Enable Unit Tests" OFF)
option(ENABLE_GEOIP "Build with GeoIP support" ON)
option(LIBRARY_BUILD "Build for libettercap only" OFF)
option(INSTALL_DESKTOP "Install ettercap desktop files" ON)


set(VALID_BUILD_TYPES Debug Release RelWithDebInfo)

if(NOT CMAKE_BUILD_TYPE)
  # Default to using "Release" as our build type.
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
    "Choose the type of build, options are: ${VALID_BUILD_TYPES}." FORCE)
endif()
list(FIND VALID_BUILD_TYPES ${CMAKE_BUILD_TYPE} contains_valid)
if(contains_valid EQUAL -1)
  message(FATAL_ERROR "Unknown CMAKE_BUILD_TYPE: '${CMAKE_BUILD_TYPE}'. Valid options are: ${VALID_BUILD_TYPES}")
endif()
unset(contains_valid)

include(CMakeDependentOption)

# If SYSTEM_LIBS is set to off, then all SYSTEM_* options will be
# set to off.
option(SYSTEM_LIBS "Search for system-provided libraries.
This is only used for libraries that we happen to also bundle.
Disabling this implies that we would only use bundled libraries." ON)

# If BUNDLED_LIBS is set to off, then all BUNDLED_* options will be
# set to off.
option(BUNDLED_LIBS
  "Use bundled libraries if system provided versions are not found (or disabled)" ON)

cmake_dependent_option(SYSTEM_CURL
  "Search for a system-provided version of Curl" ON
  SYSTEM_LIBS OFF)

cmake_dependent_option(BUNDLED_CURL
  "Use bundled version of Curl if system-provided version is not found (or disabled)" ON
  BUNDLED_LIBS OFF)

cmake_dependent_option(SYSTEM_LIBNET
  "Search for a system-provided version of LIBNET" ON
  SYSTEM_LIBS OFF)

cmake_dependent_option(BUNDLED_LIBNET
  "Use bundled version of LIBNET if system-provided version is not found (or disabled)" ON
  BUNDLED_LIBS OFF)

cmake_dependent_option(SYSTEM_LUAJIT
  "Search for a system-provided version of LUAJIT" ON
  "SYSTEM_LIBS;ENABLE_LUA" OFF)

cmake_dependent_option(BUNDLED_LUAJIT
  "Use bundled version of LUAJIT if system-provided version is not found (or disabled)" ON
  "BUNDLED_LIBS;ENABLE_LUA" OFF)

if(ENABLE_TESTS)
cmake_dependent_option(SYSTEM_LIBCHECK
  "Search for a system-provided version of LIBCHECK" ON
  SYSTEM_LIBS OFF)

cmake_dependent_option(BUNDLED_LIBCHECK
  "Use bundled version of LIBCHECK if system-provided version is not found (or disabled)" ON
  BUNDLED_LIBS OFF)
endif()

set(SPECIAL_LIB_DIR "" CACHE PATH "Special (non-traditional) root directory where headers/libraries are installed")

include(CheckVariableInHeaders)
include(EttercapOSTest)

#Check and see if we're running Darwin, specify the CMAKE_LIBARY_PATH to do so
if(OS_DARWIN)
  set(CMAKE_SYSTEM_NAME Darwin)
  set(CMAKE_LIBRARY_PATH ${SPECIAL_LIB_DIR}/lib ${CMAKE_LIBRARY_PATH})
  set(CMAKE_INCLUDE_PATH ${SPECIAL_LIB_DIR}/include ${CMAKE_INCLUDE_PATH})
else()
  set(CMAKE_LIBRARY_PATH ${CMAKE_LIBRARY_PATH} /usr/lib64 /usr/lib32)
endif()

if(LIBRARY_BUILD)
  set(ENABLE_GTK OFF)
  set(ENABLE_CURSES OFF)
  set(JUST_LIBRARY 1)
endif()

include(EttercapHeadersCheck)
include(EttercapLibCheck)
include(EttercapVariableCheck)

set(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX} CACHE PATH "Installation prefix")
set(INSTALL_SYSCONFDIR /etc CACHE PATH "System configuration directory")
set(INSTALL_LIBDIR ${INSTALL_PREFIX}/lib${LIB_SUFFIX} CACHE PATH "Library installation directory")
set(INSTALL_DATADIR ${INSTALL_PREFIX}/share CACHE PATH "Data installation directory")
set(INSTALL_EXECPREFIX ${INSTALL_PREFIX} CACHE PATH "")
set(INSTALL_BINDIR  ${INSTALL_PREFIX}/bin CACHE PATH "Binary files installation directory")
if(OS_DARWIN OR OS_BSD_FREE OR OS_WINDOWS)
  set(POLKIT_DIR ${INSTALL_PREFIX}/share/polkit-1/actions/ CACHE PATH "Polkit installation directory")
else()
#at least on ubuntu, polkit dir couldn't be /usr/local/share, but should be /usr/share
  set(POLKIT_DIR /usr/share/polkit-1/actions/ CACHE PATH "Polkit installation directory")
endif()
set(PKEXEC_INSTALL_WRAPPER org.pkexec.ettercap CACHE PATH "Name of the pkexec action file")
set(DESKTOP_DIR ${INSTALL_PREFIX}/share/applications/ CACHE PATH "Desktop file installation directory")
set(APPDATA_DIR ${INSTALL_PREFIX}/share/appdata/ CACHE PATH "Appdata file installation directory")
set(ICON_DIR ${INSTALL_PREFIX}/share/pixmaps CACHE PATH "Icon file installation directory")
set(MAN_INSTALLDIR ${INSTALL_PREFIX}/share/man CACHE PATH "Path for manual pages")

if(NOT DISABLE_RPATH)
  # Ensure that, when we link to stuff outside of our build path, we include the
  # library dir path in our RPATH.
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
  set(CMAKE_MACOSX_RPATH 1)
endif()

# set general build flags for debug build-type
set(CMAKE_C_FLAGS_DEBUG "-O0 -ggdb3 -DDEBUG -Wall -Wno-pointer-sign -D_FORTIFY_SOURCE=2 -Wformat -Wformat-security -Werror=format-security -Wextra -Wredundant-decls" CACHE STRING "" FORCE)
## append ASAN build flags if compiler version has support
#if("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU")
#   if(CMAKE_C_COMPILER_VERSION VERSION_GREATER 4.8)
#      set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address
#         -fno-omit-frame-pointer" CACHE STRING "" FORCE)
#      message("Building with ASAN support (GNU compiler)")
#   else()
#      message("Building without ASAN support (GNU compiler)")
#   endif()
#elseif("${CMAKE_C_COMPILER_ID}" STREQUAL "Clang")
#   if(CMAKE_C_COMPILER_VERSION VERSION_GREATER 3.1)
#      set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address
#         -fno-omit-frame-pointer" CACHE STRING "" FORCE)
#      message("Building with ASAN support (Clang compiler)")
#   elseif(CMAKE_C_COMPILER_VERSION VERSION_GREATER 3.1)
#      message("Building without ASAN support (Clang compiler)")
#   endif()
#endif()

# set build flags for release build-type
set(CMAKE_C_FLAGS_RELEASE "-O2 -w -D_FORTIFY_SOURCE=2" CACHE STRING "" FORCE)

if(OS_DARWIN)
set(CMAKE_EXE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "-undefined dynamic_lookup" CACHE STRING "" FORCE)
endif()

if(ENABLE_LUA)
  include(EttercapLuajit)
  set(HAVE_EC_LUA 1)
endif()

set(EC_INCLUDE_PATH ${CMAKE_CURRENT_BINARY_DIR}/include ${CMAKE_SOURCE_DIR}/include ${EC_INCLUDE})
include_directories(${EC_INCLUDE_PATH})

add_subdirectory(src)

if(INSTALL_DESKTOP)
  add_subdirectory(desktop)
endif()

if(HAVE_PLUGINS)
    if(OS_MINGW)
        message("Sorry, plugins support on Windows is currently unavailable")
    else()
        add_subdirectory(plug-ins)
    endif()
endif()
add_subdirectory(utils)
add_subdirectory(share)
add_subdirectory(man)

if(ENABLE_IPV6)
    set(WITH_IPV6 TRUE)
endif()

# This line should ALWAYS be after all options are defined
configure_file(include/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/include/config.h)

if(ENABLE_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# uninstall target
configure_file(
    "${CMAKE_SCRIPT_PATH}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)

# Add a target that will ensure that the build directory is properly cleaned.
add_custom_target(clean-all
  COMMAND ${CMAKE_BUILD_TOOL} clean
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SCRIPT_PATH}/clean-all.cmake
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
endif()

include(FeatureSummary)
feature_summary(WHAT ALL)
