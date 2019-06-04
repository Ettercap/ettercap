# Copyright 2018 Ettercap Development Team.
#
# Distributed under the GPL.
#
# - Find CHECK
# Find Check, the unit testing framework for C.
#
# Once done this will define:
#
#  CHECK_FOUND        - System has Check
#  CHECK_INCLUDE_DIRS - The Check include directories
#  CHECK_LIBRARIES    - The libraries needed to use Check
#  CHECK_LDFLAGS      - Additional required linker flags needed by check
#  CHECK_CFLAGS       - Compiler switches required for using Check
#  CHECK_VERSION      - The version of CHECK found
#
# NOTE: If you intend to use version checking, CMake 2.6.2 or later may be
# required.
#
# TODO: Be less pkg-config dependent.
#

find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
  pkg_search_module(PC_CHECK QUIET IMPORTED_TARGET check libcheck)
  # If PC_CHECK is found, we will have an imported target named
  # PkgConfig::PC_CHECK that can be passed directly as an argument to
  # target_link_libraries().
  # Meaning that we don't need to worry about anything below this point.
endif()

find_path(CHECK_INCLUDE_DIR check.h
  PATHS
  ${PC_CHECK_INCLUDEDIR}
  ${PC_CHECK_INCLUDE_DIRS}
)

find_library(CHECK_LIBRARY check
  PATHS
  ${PC_CHECK_LIBDIR}
  ${PC_CHECK_LIBRARY_DIRS}
)

if(PC_CHECK_VERSION)
  set(CHECK_VERSION ${PC_CHECK_VERSION})
else()
  function(extract_version FILENAME VARNAME)
    file(STRINGS ${FILENAME} _version_str
      REGEX "^#define ${VARNAME}.*")

  string(REGEX MATCH "[0-9]+" temp_var "${_version_str}")

  set(${VARNAME} ${temp_var} PARENT_SCOPE)
  endfunction()

  # Try to find the version number.
  set(HEADER_FILE "${CHECK_INCLUDE_DIR}/check.h")
  if(EXISTS ${HEADER_FILE})
    extract_version(${HEADER_FILE} CHECK_MAJOR_VERSION)
    extract_version(${HEADER_FILE} CHECK_MINOR_VERSION)
    extract_version(${HEADER_FILE} CHECK_MICRO_VERSION)
    set(CHECK_VERSION
      "${CHECK_MAJOR_VERSION}.${CHECK_MINOR_VERSION}.${CHECK_MICRO_VERSION}")
  endif()
endif()

# Handle the QUIETLY and REQUIRED arguments and set CHECK_FOUND to TRUE if
# all listed variables are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CHECK
  REQUIRED_VARS
    CHECK_LIBRARY
    CHECK_INCLUDE_DIR
  VERSION_VAR CHECK_VERSION
)

if(CHECK_FOUND)
  set(CHECK_LIBRARIES ${CHECK_LIBRARY})
  set(CHECK_INCLUDE_DIRS ${CHECK_INCLUDE_DIR})

  if(PC_CHECK_FOUND)
    set(CHECK_LDFLAGS ${PC_CHECK_LDFLAGS})
    set(CHECK_CFLAGS ${PC_CHECK_CFLAGS})
  endif()

  if(NOT TARGET CHECK::CHECK)
    add_library(CHECK::CHECK UNKNOWN IMPORTED)
    set_target_properties(CHECK::CHECK PROPERTIES
      IMPORTED_LOCATION "${CHECK_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${CHECK_INCLUDE_DIR}"
      INTERFACE_LINK_LIBRARIES "${CHECK_LDFLAGS}")
  endif()

endif()

mark_as_advanced(CHECK_INCLUDE_DIR CHECK_LIBRARY)
