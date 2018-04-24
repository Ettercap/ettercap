# Copyright 2018 Ettercap Development Team.
#
# Distributed under the GPL.
#
# - Find PCRE
# Find the Perl compatible regular expressions C library and includes.
#
#  PCRE_INCLUDE_DIRS - Where to find pcre.h.
#  PCRE_LIBRARIES    - List of libraries when using PCRE.
#  PCRE_FOUND        - True if PCRE is found.
#  PCRE_VERSION      - The version of PCRE found
#
# The only (optional) component this module looks for is pcreposix.
# That's because it's the only one we need at the moment.
#
#  PCRE_PCREPOSIX_LIBRARY    - the pcreposix library found.
#  PCRE_pcreposix_FOUND      - True if pcreposix is found.
#

find_package(PkgConfig QUIET)
pkg_search_module(PC_PCRE QUIET IMPORTED_TARGET libpcre)
# pkg-config --list-all | grep pcre

# Look for the header file
find_path(PCRE_INCLUDE_DIR pcre.h
  PATHS
    ${PC_PCRE_INCLUDE_DIRS}
)

# Look for the library.
find_library(PCRE_LIBRARY pcre
  PATHS
    ${PC_PCRE_LIBRARY_DIRS}
)

# Handle (optional) components (i.e pcreposix).
if(PCRE_FIND_COMPONENTS STREQUAL "pcreposix")
  pkg_search_module(PC_PCREPOSIX QUIET IMPORTED_TARGET libpcreposix)

  find_library(PCRE_PCREPOSIX_LIBRARY pcreposix
    PATHS
    ${PC_PCRE_LIBRARY_DIRS}
    ${PC_PCREPOSIX_LIBRARY_DIRS}
  )

  if(PCRE_PCREPOSIX_LIBRARY)
    set(PCRE_pcreposix_FOUND 1)
  endif()
endif()

# Get version string.
if(PC_PCRE_VERSION)
  set(PCRE_VERSION ${PC_PCRE_VERSION})
else()
  function(extract_version FILENAME DEFNAME VARIABLE)
    file(STRINGS ${FILENAME} pcre_version_str
      REGEX "^#define[\t ]+${DEFNAME}[\t ]+.*")

    string(REGEX REPLACE "^#define[\t ]+${DEFNAME}[\t ]+([0-9]+).*"
      "\\1" temp_var "${pcre_version_str}")

    set(${VARIABLE} ${temp_var} PARENT_SCOPE)
  endfunction()

  # Try to find the version number.
  set(HEADER_FILE "${PCRE_INCLUDE_DIR}/pcre.h")
  if(EXISTS ${HEADER_FILE})
    extract_version(${HEADER_FILE} PCRE_MAJOR PCRE_VERSION_MAJOR)
    extract_version(${HEADER_FILE} PCRE_MINOR PCRE_VERSION_MINOR)
    set(PCRE_VERSION
      "${PCRE_VERSION_MAJOR}.${PCRE_VERSION_MINOR}")
  endif()
endif()

# Handle the QUIETLY and REQUIRED arguments and set PCRE_FOUND to TRUE if
# all listed variables are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE
  REQUIRED_VARS
    PCRE_LIBRARY
    PCRE_INCLUDE_DIR
  HANDLE_COMPONENTS
  VERSION_VAR PCRE_VERSION
)

if(PCRE_FOUND)
  set(PCRE_LIBRARIES ${PCRE_LIBRARY} ${PCRE_PCREPOSIX_LIBRARY})
  set(PCRE_INCLUDE_DIRS ${PCRE_INCLUDE_DIR})
  # For compatibility with our old findPCRE.cmake
  set(PCRE_VERSION_STRING ${PCRE_VERSION})

  if(NOT TARGET PCRE::PCRE)
    add_library(PCRE::PCRE UNKNOWN IMPORTED)
    set_target_properties(PCRE::PCRE PROPERTIES
      IMPORTED_LOCATION "${PCRE_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${PCRE_INCLUDE_DIR}")
  endif()

  if(PCRE_pcreposix_FOUND AND NOT TARGET PCRE::PCREPOSIX)
    add_library(PCRE::PCREPOSIX UNKNOWN IMPORTED)
    set_target_properties(PCRE::PCREPOSIX PROPERTIES
      IMPORTED_LOCATION "${PCRE_PCREPOSIX_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${PCRE_INCLUDE_DIR}")
  endif()

endif()

mark_as_advanced(PCRE_INCLUDE_DIR PCRE_LIBRARY PCRE_PCREPOSIX_LIBRARY)
