# Copyright 2018 Ettercap Development Team.
#
# Distributed under the GPL.
#
# - Find GeoIP
# Find the native GeoIP includes and library
#
#  GEOIP_INCLUDE_DIRS - Where to find GeoIP.h, etc.
#  GEOIP_LIBRARIES    - The GeoIP library.
#  GEOIP_FOUND        - True if GeoIP is found.

find_package(PkgConfig QUIET)
pkg_search_module(PC_GEOIP QUIET IMPORTED_TARGET geoip)

# Find the header
find_path(GEOIP_INCLUDE_DIR GeoIP.h
  PATHS
    ${PC_GEOIP_INCLUDE_DIRS}
    C:/GeoIP/
  PATH_SUFFIXES Include include
)

# GEOIP_USE_STATIC_LIBS
# ------------------------------
# When building with MSVC, set this variable to ``TRUE`` or ``1`` to look for
# static libraries. Starting with commit 204cc59, they happened have a "lib"
# prefix.
# https://github.com/maxmind/geoip-api-c/pull/102

set(names)
if(MSVC AND GEOIP_USE_STATIC_LIBS)
  set(names libGeoIP)

  set(GEOIP_DEFINITIONS
    ${GEOIP_DEFINITIONS}
    -DGEOIP_STATIC
  )

else()
  set(names GeoIP)
endif()

# Find the library
find_library(GEOIP_LIBRARY
  NAMES ${names}
  PATHS
    ${PC_GEOIP_LIBRARY_DIRS}
    C:/GeoIP/
  PATH_SUFFIXES Lib lib
)

if(PC_GEOIP_VERSION)
  set(GEOIP_VERSION ${PC_GEOIP_VERSION})
else()
  if(GEOIP_LIBRARY)
    # The following super-fragile exercise can't work if GEOIP_LIBRARY
    # is an export library. That's because GeoIP's export libraries don't
    # actually hold GeoIP's version string (they on hold the function to query
    # it at runtime).
    # In theses cases we can't find (and report) the version we found.
    if(NOT GEOIP_LIBRARY MATCHES ".dll.a" AND
      NOT GEOIP_LIBRARY MATCHES "/GeoIP.lib$")
      file(STRINGS ${GEOIP_LIBRARY} GEOIP_VERSION
        # LIMIT_COUNT 1
        LENGTH_MINIMUM 5
        LENGTH_MAXIMUM 6
        NEWLINE_CONSUME
        REGEX "^[1]+[.][0-9]+.[0-9]+$"
      )
    endif()
  endif()
endif()

# handle the QUIETLY and REQUIRED arguments and set GEOIP_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GEOIP
  REQUIRED_VARS
    GEOIP_LIBRARY
    GEOIP_INCLUDE_DIR
  VERSION_VAR GEOIP_VERSION
)

if(GEOIP_FOUND)
  set(GEOIP_INCLUDE_DIRS ${GEOIP_INCLUDE_DIR})
  set(GEOIP_LIBRARIES ${GEOIP_LIBRARY})

  if(NOT TARGET GEOIP::GEOIP)
    add_library(GEOIP::GEOIP UNKNOWN IMPORTED)
    set_target_properties(GEOIP::GEOIP PROPERTIES
      IMPORTED_LOCATION "${GEOIP_LIBRARY}"
      INTERFACE_COMPILE_DEFINITIONS "${GEOIP_DEFINITIONS}"
      INTERFACE_INCLUDE_DIRECTORIES "${GEOIP_INCLUDE_DIR}")
  endif()
endif()

mark_as_advanced(GEOIP_LIBRARIES GEOIP_INCLUDE_DIRS)
