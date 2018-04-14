cmake_minimum_required(VERSION 3.0 FATAL_ERROR)
project(ettercap VERSION 0.8.3 LANGUAGES C)

# Include our cmake modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")
set(CMAKE_SCRIPT_PATH "${CMAKE_SOURCE_DIR}/cmake/Scripts")

include(EttercapMacrosAndFunctions)

ensure_out_of_source_build()

include(EttercapOSTest)

# USER OPTIONS
# ============

include(CMakeDependentOption)

cmake_dependent_option(ENABLE_CURSES "Enable curses interface" ON
  "NOT OS_WINDOWS;NOT LIBRARY_BUILD" OFF)
cmake_dependent_option(CURSES_NEED_WIDE "Enable Unicode functionality in \
curses (wide character support)" OFF
  "ENABLE_CURSES" OFF)

cmake_dependent_option(ENABLE_GTK "Enable GTK interface" ON
  "NOT LIBRARY_BUILD" OFF)
option(ENABLE_PLUGINS "Enable plugins support" ON)
option(ENABLE_IPV6 "Enable IPv6 support" OFF)
option(ENABLE_LUA "Enable LUA support (EXPERIMENTAL)" OFF)
option(ENABLE_PDF_DOCS "Enable PDF document generation" OFF)
option(ENABLE_TESTS "Enable Unit Tests" OFF)
option(ENABLE_GEOIP "Build with GeoIP support" ON)
option(LIBRARY_BUILD "Build for libettercap only" OFF)

cmake_dependent_option(INSTALL_DESKTOP "Install ettercap desktop files" ON
  "NOT OS_WINDOWS" OFF)

# If SYSTEM_LIBS is set to off, then all SYSTEM_* options will be
# set to off.
option(SYSTEM_LIBS "Search for system-provided libraries.
This is only used for libraries that we happen to also bundle.
Disabling this implies that we would only use bundled libraries." ON)

# If BUNDLED_LIBS is set to off, then all BUNDLED_* options will be
# set to off.
option(BUNDLED_LIBS
  "Use bundled libraries if system provided \
  versions are not found (or disabled)" ON
)

cmake_dependent_option(SYSTEM_CURL
  "Search for a system-provided version of Curl" ON
  SYSTEM_LIBS OFF
)

cmake_dependent_option(BUNDLED_CURL
  "Use bundled version of Curl if system-provided \
  version is not found (or disabled)" ON
  BUNDLED_LIBS OFF
)

cmake_dependent_option(SYSTEM_LIBNET
  "Search for a system-provided version of LIBNET" ON
  SYSTEM_LIBS OFF
)

cmake_dependent_option(BUNDLED_LIBNET
  "Use bundled version of LIBNET if system-provided \
  version is not found (or disabled)" ON
  BUNDLED_LIBS OFF
)

cmake_dependent_option(SYSTEM_LUAJIT
  "Search for a system-provided version of LUAJIT" ON
  "SYSTEM_LIBS;ENABLE_LUA" OFF
)

cmake_dependent_option(BUNDLED_LUAJIT
  "Use bundled version of LUAJIT if system-provided \
  version is not found (or disabled)" ON
  "BUNDLED_LIBS;ENABLE_LUA" OFF
)

if(ENABLE_TESTS)
  cmake_dependent_option(SYSTEM_LIBCHECK
    "Search for a system-provided version of LIBCHECK" ON
    SYSTEM_LIBS OFF
  )

  cmake_dependent_option(BUNDLED_LIBCHECK
    "Use bundled version of LIBCHECK if system-provided \
    version is not found (or disabled)" ON
    BUNDLED_LIBS OFF
  )
endif()

# INSTALL AND/OR OUTPUT DIRECTORIES
# =================================

set(INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX} CACHE PATH "Installation prefix")

if(UNIX)
  set(INSTALL_SYSCONFDIR /etc CACHE PATH "System configuration directory")
  else()
  set(INSTALL_SYSCONFDIR
    ${INSTALL_PREFIX}/etc CACHE PATH "System configuration directory"
  )
endif()

set(INSTALL_LIBDIR
  ${INSTALL_PREFIX}/lib${LIB_SUFFIX} CACHE PATH
  "Library installation directory"
)

set(INSTALL_DATADIR
  ${INSTALL_PREFIX}/share CACHE PATH "Data installation directory"
)

set(INSTALL_EXECPREFIX ${INSTALL_PREFIX} CACHE PATH "")
set(INSTALL_BINDIR
  ${INSTALL_PREFIX}/bin CACHE PATH "Binary files installation directory"
)

if(OS_DARWIN OR OS_WINDOWS)
  set(POLKIT_DIR
    ${INSTALL_PREFIX}/share/polkit-1/actions/ CACHE PATH
    "Polkit installation directory"
  )
else()
# at least on ubuntu, polkit dir couldn't be /usr/local/share,
# but should be /usr/share
  set(POLKIT_DIR
    /usr/share/polkit-1/actions/ CACHE PATH "Polkit installation directory"
  )
endif()

set(PKEXEC_INSTALL_WRAPPER
  org.pkexec.ettercap CACHE PATH "Name of the pkexec action file"
)

set(DESKTOP_DIR
  ${INSTALL_PREFIX}/share/applications/ CACHE PATH
  "Desktop file installation directory"
)

set(APPDATA_DIR
  ${INSTALL_PREFIX}/share/appdata/ CACHE PATH
  "Appdata file installation directory"
)

set(ICON_DIR
  ${INSTALL_PREFIX}/share/pixmaps CACHE PATH "Icon file installation directory"
)

set(MAN_INSTALLDIR
  ${INSTALL_PREFIX}/share/man CACHE PATH "Path for manual pages"
)

# XXX - remove this or move this into correct section
if(NOT DISABLE_RPATH)
  # Ensure that, when we link to stuff outside of our build path, we include the
  # library dir path in our RPATH.
  set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
  set(CMAKE_MACOSX_RPATH 1)
endif()

# GLOBAL BUILD PARAMETERS
# =======================

# Global compile definitions
# --------------------------

add_definitions(-D_FORTIFY_SOURCE=2)

# Global include directories
# --------------------------

include_directories(
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/include
)

# Automatically add CMAKE_CURRENT_SOURCE_DIR and CMAKE_CURRENT_BINARY_DIR to
# the include directories in every processed CMakeLists.txt.
set(CMAKE_INCLUDE_CURRENT_DIR 1)

# Order the include directories so that directories which are in the source or
# build tree always come before directories outside the project.
set(CMAKE_INCLUDE_DIRECTORIES_PROJECT_BEFORE 1)

if(NOT OS_DARWIN AND NOT OS_WINDOWS)
  set(FIND_LIBRARY_USE_LIB32_PATHS 1)
  set(FIND_LIBRARY_USE_LIB64_PATHS 1)
endif()

# Global linker flags
# -------------------

if(OS_DARWIN)
set(CMAKE_EXE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
endif()

# Set build Type
# --------------

# XXX - move this line to EttercapOSTest.cmake
get_property(IS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

set(VALID_BUILD_TYPES "Debug, Release, RelWithDebInfo and MinSizeRel")
if(NOT CMAKE_BUILD_TYPE AND NOT "${IS_MULTI_CONFIG}")
  # On "single-configuration generators", default to the "Release" build type.
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
    "Choose the type of build, options are: ${VALID_BUILD_TYPES}." FORCE
  )
endif()

# Debug build Type
# ----------------

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_CONFIGURATION_TYPES)
# Set build flags for debug builds

  add_definitions(-DDEBUG)
  add_definitions(-D_DEBUG)

  # Check and add compiler options if they exist.
  # ---------------------------------------------
  #
  # You may add any kind of compiler flag to this.
  # If your compiler supports it, it will be added, if not, it will be skipped.
  check_and_add_compiler_option(-O0)
  check_and_add_compiler_option(-ggdb3)
  check_and_add_compiler_option(-Wall)
  check_and_add_compiler_option(-Wno-pointer-sign)
  check_and_add_compiler_option(-Wformat)
  check_and_add_compiler_option(-Werror=format-security)
  check_and_add_compiler_option(-Wextra)
  check_and_add_compiler_option(-Wredundant-decls)
  check_and_add_compiler_option(-W4) # MSVC only
  check_and_add_compiler_option(-Wused-but-marked-unused) # Clang/llVM only
endif()

# SUBDIRECTORIES
# ==============

include(EttercapHeadersCheck)
include(EttercapLibCheck)
include(EttercapVariableCheck)

if(ENABLE_LUA)
  include(EttercapLuajit)
  set(HAVE_EC_LUA 1)
endif()

add_subdirectory(src)

if(INSTALL_DESKTOP)
  add_subdirectory(desktop)
endif()

if(HAVE_PLUGINS)
  if(OS_WINDOWS)
    message("Sorry, plugins support on Windows is currently unavailable")
  else()
    add_subdirectory(plug-ins)
  endif()
endif()
add_subdirectory(utils)
add_subdirectory(share)
add_subdirectory(man)

if(ENABLE_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# MISCELLANEOUS
# =============

if(ENABLE_IPV6)
  set(WITH_IPV6 TRUE)
endif()

# This line should ALWAYS be after all options are defined
configure_file(include/config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/include/config.h
)

# UNINSTALLATION
# ==============

# uninstall target
configure_file(
  "${CMAKE_SCRIPT_PATH}/cmake_uninstall.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
  IMMEDIATE @ONLY
)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake
)

# Add a target that will ensure that the build directory is properly cleaned.
add_custom_target(clean-all
  COMMAND ${CMAKE_BUILD_TOOL} clean
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_SCRIPT_PATH}/clean-all.cmake
)

# XXX - Add a nicer build summary at the end

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
