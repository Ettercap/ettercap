# Copyright 2018 Ettercap Development Team.
#
# Distributed under the GPL.
#
# - Find LUAJIT
# Find library and includes of the Just-in-time compiler for Lua.
#
#  LUAJIT_INCLUDE_DIRS - Where to find pcre.h.
#  LUAJIT_LIBRARIES    - List of libraries when using LUAJIT.
#  LUAJIT_FOUND        - True if LUAJIT is found.
#  LUAJIT_VERSION      - The version of LUAJIT found
#

find_package(PkgConfig QUIET)
pkg_search_module(PC_LUAJIT QUIET IMPORTED_TARGET luajit)

# Look for the header file
find_path(LUAJIT_INCLUDE_DIR luajit.h
  PATHS
    ${PC_LUAJIT_INCLUDE_DIRS}
  PATH_SUFFIXES luajit-2.1 luajit-2.0 luajit
)

#Look for the library
set(names luajit-5.1)
if(WIN32)
  list(APPEND names lua51)
endif()

find_library(LUAJIT_LIBRARY NAMES ${names}
  PATHS
    ${PC_LUAJIT_LIBRARY_DIRS}
)

# Get version string.
if(PC_LUAJIT_VERSION)
  set(LUAJIT_VERSION ${PC_LUAJIT_VERSION})
else()
  # Get '#define LUAJIT_VERSION		"LuaJIT X.X.X"'
  file(STRINGS ${LUAJIT_INCLUDE_DIR}/luajit.h LUAJIT_HEADER_DUMP
    LENGTH_MINIMUM 30
    LENGTH_MAXIMUM 40
    REGEX "^#define LUAJIT_VERSION[\t]+.*"
  )

  string(REGEX MATCH "([0-9]+.)([0-9]+[.]*)([0-9]*)"
    LUAJIT_VERSION
    "${LUAJIT_HEADER_DUMP}"
  )
endif()

# Handle the QUIETLY and REQUIRED arguments and set LUAJIT_FOUND to TRUE if
# all listed variables are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LUAJIT
  REQUIRED_VARS
    LUAJIT_LIBRARY
    LUAJIT_INCLUDE_DIR
  VERSION_VAR LUAJIT_VERSION
)

if(LUAJIT_FOUND)
  set(LUAJIT_LIBRARIES ${LUAJIT_LIBRARY})
  set(LUAJIT_INCLUDE_DIRS ${LUAJIT_INCLUDE_DIR})

  if(NOT TARGET LUAJIT::LUAJIT)
    add_library(LUAJIT::LUAJIT UNKNOWN IMPORTED)
    set_target_properties(LUAJIT::LUAJIT PROPERTIES
      IMPORTED_LOCATION "${LUAJIT_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${LUAJIT_INCLUDE_DIR}")
  endif()

endif()

mark_as_advanced(LUAJIT_INCLUDE_DIR LUAJIT_LIBRARY)
