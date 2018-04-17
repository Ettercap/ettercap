# Copyright 2018 Ettercap Development Team.
#
# Distributed under the GPL.
#
# - Find Pthreads-win32 (a.k.a. pthreads4w)
# Find Pthreads-win32 (a.k.a. pthreads4w), the Open Source Software
# implementation of the Threads component of the POSIX 1003.1c 1995
# Standard (or later) for Microsoft's Windows.
#
# NOTE:
# This module is derived from a FindPthreads.cmake module I found floating
# around the Internet.
# It has been renamed to FindPTHREADS-WIN32.cmake (which is subject to change
# at any time) to avoid confusion/collision etc.
#
# This module defines these variables:
#
#  PTHREADS-WIN32_FOUND       - True if the Pthreads-win32 library was found
#  PTHREADS-WIN32_LIBRARY     - The location of the Pthreads-win32 library
#  PTHREADS-WIN32_INCLUDE_DIR - Pthreads-win32's include directory
#  PTHREADS-WIN32_DEFINITIONS - Preprocessor definitions to define
#  PTHREADS-WIN32_VERSION     - The version of Pthreads-win32 found (x.y.z)
#
# Hints and Build Customization
# =============================
#
# PTHREADS-WIN32_EXCEPTION_SCHEME
# -------------------------------
#
# This module responds to the PTHREADS-WIN32_EXCEPTION_SCHEME
# variable on to allow the user to control the library linked
# against. Pthreads-win32 provides the ability to link against
# a version of the library with exception handling.
# IT IS NOT RECOMMENDED THAT YOU CHANGE PTHREADS-WIN32_EXCEPTION_SCHEME
# TO ANYTHING OTHER THAN "C" BECAUSE MOST POSIX THREAD IMPLEMENTATIONS
# DO NOT SUPPORT STACK UNWINDING.
#       C  = no exceptions (default)
#          (NOTE: This is the default scheme on most POSIX thread
#           implementations and what you should probably be using)
#       CE = C++ Exception Handling
#       SE = Structure Exception Handling (MSVC only)
#
# PTHREADS-WIN32_USE_STATIC_LIBS
# ------------------------------
#
# Set this variable to ``TRUE`` or ``1`` to look for static libraries.
# This is much easier to achieve on MinGW then VC++ because official
# Pthreads-win32 builds don't separate libraries by any kind of naming
# scheme. We can really only tell for MinGW because of the different
# file extension.
# With VC++/MSVC you have three choices:

# 1. Add a "lib" prefix to your static Pthreads-win32 libraries
# 2. Use Microsoft's vcpkg port of Pthreads-win32 and make sure
#    to set VCPKG_TARGET_TRIPLET and/or the environment
#    VCPKG_DEFAULT_TRIPLET to XXX-windows-static
#    (e.g x86-windows-static). See the command 'vcpkg help triplet'
#    for help.
# 3. Use my fork. 'My' is, me Ali Abdulkadir <autostart.ini@gmail.com>
#    the author of this module. See section 'Quasi Self-Promotion' below.
#
# NOTE:
# Pthreads-win32 is covered by the GNU Lesser General Public License.
# Linking close-sourced projects with static Pthreads-win32 builds is a
# violation of said license.

# Quasi Self-Promotion
# --------------------
#
# https://github.com/sgeto/pthreads-win32/blob/privat/README.md
# https://ci.appveyor.com/project/sgeto/pthreads-win32


# Define a default exception scheme to link against
# and validate user choice.
if(NOT DEFINED PTHREADS-WIN32_EXCEPTION_SCHEME)
  # Assign default if needed
  set(PTHREADS-WIN32_EXCEPTION_SCHEME "C")
else()
  # Validate
  if(NOT PTHREADS-WIN32_EXCEPTION_SCHEME STREQUAL "C" AND
  NOT PTHREADS-WIN32_EXCEPTION_SCHEME STREQUAL "CE" AND
  NOT PTHREADS-WIN32_EXCEPTION_SCHEME STREQUAL "SE")

  message(FATAL_ERROR "See documentation for ${CMAKE_CURRENT_LIST_FILE};
  Only C, CE, and SE modes are allowed")

  endif()

  if(NOT MSVC AND PTHREADS-WIN32_EXCEPTION_SCHEME STREQUAL "SE")
    message(FATAL_ERROR "Structured Exception Handling is MSVC only")
  endif()

endif()

# Support preference of static libs by adjusting CMAKE_FIND_LIBRARY_SUFFIXES
# and/or CMAKE_FIND_LIBRARY_PREFIXES
if(PTHREADS-WIN32_USE_STATIC_LIBS)
# XXX - make sure we really got an static lib (via try_compile?)
  if(MSVC)
    list(APPEND CMAKE_FIND_LIBRARY_PREFIXES lib)
  elseif(MINGW)
    list(REVERSE CMAKE_FIND_LIBRARY_SUFFIXES)
  endif()

  set(PTHREADS-WIN32_DEFINITIONS
    ${PTHREADS-WIN32_DEFINITIONS}
    -DPTW32_STATIC_LIB
  )
endif()

# Find the header file
find_path(PTHREADS-WIN32_INCLUDE_DIR pthread.h
  DOC "The Pthreads-win32 include directory"
  HINTS
  $ENV{PTHREADS-WIN32_INCLUDE_PATH}
  $ENV{PTHREADS-WIN32_ROOT}
  PATH_SUFFIXES include
)

if(PTHREADS-WIN32_INCLUDE_DIR)
# Ensure that we found Pthreads-win32's pthread.h
  include(CheckSymbolExists)
  include(CMakePushCheckState)
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_INCLUDES ${PTHREADS-WIN32_INCLUDE_DIR})
  check_symbol_exists(PTHREAD_H
    "pthread.h" HAVE_PTHREADSWIN32_PTHREADS_H
  )
  if(NOT HAVE_PTHREADSWIN32_PTHREADS_H)
    message(FATAL_ERROR "
Instead of Pthreads-win32, another POSIX Thread implementation was found in \
your compiler's path here:\n\
${PTHREADS-WIN32_INCLUDE_DIR}\n\
To use Pthreads-win32, make sure it's included FIRST.\n")
  endif()
  cmake_pop_check_state()
endif()

# Find the library
set(names)
if(MSVC)
  set(names pthreadV${PTHREADS-WIN32_EXCEPTION_SCHEME}2)
elseif(MINGW)
  set(names pthreadG${PTHREADS-WIN32_EXCEPTION_SCHEME}2)
endif()

if(VCPKG_TARGET_TRIPLET OR "$ENV{VCPKG_DEFAULT_TRIPLET}")
  # Special case:
  # Microsoft's vcpkg decided to rename pthreadV${PTHREADS_EXCEPTION_SCHEME}2
  # to simply pthreads.lib and to not support PTHREADS_EXCEPTION_SCHEME.
  # This may change so we look for both libs.
  #
  # In case you *really* need to disable this behavior
  # set this (internal) variable.
  if(NOT __skipvcpkg AND NOT MINGW)
    list(APPEND names pthreads)
  endif()
endif()

# Support the directory structure of the
# pre-build binaries folder.
# (e.i Pre-built.2/lib/x64 Pre-built.2/lib/x86)
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  if(CMAKE_PREFIX_PATH OR
    "$ENV{CMAKE_PREFIX_PATH}") # may be set by user
    set(CMAKE_LIBRARY_ARCHITECTURE x64)
  endif()
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
  if(CMAKE_PREFIX_PATH OR
    "$ENV{CMAKE_PREFIX_PATH}") # may be set by user
    set(CMAKE_LIBRARY_ARCHITECTURE x86)
  endif()
endif()

find_library(PTHREADS-WIN32_LIBRARY NAMES ${names}
  DOC "The Pthreads-win32 library"
  HINTS
  $ENV{PTHREADS-WIN32_LIBRARY_PATH}
  $ENV{PTHREADS-WIN32_ROOT}
  PATH_SUFFIXES lib
)

if(PTHREADS-WIN32_INCLUDE_DIR)

  # Sanity check to ensure no other pthread.h (I know of) is polluting our
  # include path.
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_QUIET 1)
  check_symbol_exists(WIN_PTHREADS_H
    "pthread.h" HAVE_WIN_PTHREADS_H
  )

  if(HAVE_WIN_PTHREADS_H)
    message(WARNING "
winpthreads was found in your compiler's path and BEFORE \
Pthreads-win32.\n\
To use Pthreads-win32, make sure it's included FIRST.\n")
  endif()
  check_symbol_exists(_PTHREAD_H
    "pthread.h" HAVE_UNIX_PTHREADS_H
  )

  if(HAVE_UNIX_PTHREADS_H)
    message(WARNING "
Another POSIX Thread implementation was found in your compiler's path and \
BEFORE Pthreads-win32.\n\
To use Pthreads-win32, make sure it's included FIRST.\n")
  endif()
  cmake_pop_check_state()

# Get version
  cmake_push_check_state(RESET)
  set(CMAKE_REQUIRED_INCLUDES ${PTHREADS-WIN32_INCLUDE_DIR})
  include(CheckIncludeFile)
  check_include_file(_ptw32.h HAVE__PTW32_H)
  cmake_pop_check_state()

  if(HAVE__PTW32_H)
    set(PTW32_VERSION_HEADER ${PTHREADS-WIN32_INCLUDE_DIR}/_ptw32.h)
  else()
    set(PTW32_VERSION_HEADER ${PTHREADS-WIN32_INCLUDE_DIR}/pthread.h)
  endif()

  # Get '#define PTW32_VERSION X,X,X,X'
  file(STRINGS ${PTW32_VERSION_HEADER} PTW32_HEADER_DUMP
    LIMIT_COUNT 60
    LENGTH_MINIMUM 10
    LENGTH_MAXIMUM 40
    REGEX "[0-9]+[,][0-9]+[,][0-9]+$"
  )

# Get 'X,X,X'
  string(REGEX MATCH "[0-9]+[,][0-9]+[,][0-9]+"
    PTW32_PRE_VERSION
    "${PTW32_HEADER_DUMP}"
  )
  # Convert 'X,X,X' to 'X.X.X'
  string(REPLACE "," "." PTHREADS-WIN32_VERSION ${PTW32_PRE_VERSION})
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PTHREADS-WIN32
  REQUIRED_VARS
  PTHREADS-WIN32_LIBRARY
  PTHREADS-WIN32_INCLUDE_DIR
  VERSION_VAR PTHREADS-WIN32_VERSION
)

if(PTHREADS-WIN32_FOUND)
  set(PTHREADS-WIN32_INCLUDE_DIRS ${PTHREADS-WIN32_INCLUDE_DIR})
  set(PTHREADS-WIN32_LIBRARIES ${PTHREADS-WIN32_LIBRARY})
endif()

mark_as_advanced(PTHREADS-WIN32_INCLUDE_DIR PTHREADS-WIN32_LIBRARY)

# Restore the original find library ordering
if(PTHREADS-WIN32_USE_STATIC_LIBS)
  if(MSVC)
    list(REMOVE_ITEM CMAKE_FIND_LIBRARY_PREFIXES lib)
  elseif(MINGW)
    list(REVERSE CMAKE_FIND_LIBRARY_SUFFIXES)
  endif()
endif()
