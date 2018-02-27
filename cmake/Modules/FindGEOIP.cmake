#
# - Find GeoIP
# Find the native GeoIP includes and library
#
#  GEOIP_INCLUDE_DIRS - where to find GeoIP.h, etc.
#  GEOIP_LIBRARIES    - List of libraries when using GeoIP.
#  GEOIP_FOUND        - True if GeoIP found.

if(GEOIP_INCLUDE_DIRS)
  # Already in cache, be silent
  set(GEOIP_FIND_QUIETLY TRUE)
endif()

# Users may set the (environment) variable GEOIP_ROOT
# to point cmake to the *root* of a directory with include
# and lib subdirectories for GeoIP
if(GEOIP_ROOT)
  set(GEOIP_ROOT PATHS ${GEOIP_ROOT} NO_DEFAULT_PATH)
else()
  set(GEOIP_ROOT $ENV{GEOIP_ROOT})
endif()

find_package(PkgConfig)
pkg_search_module(GEOIP geoip)

# Find the header
find_path(GEOIP_INCLUDE_DIR GeoIP.h
  HINTS
    "${GEOIP_INCLUDEDIR}"
    "${GEOIP_ROOT}"
  PATH_SUFFIXES include Include
)

# Find the library
find_library(GEOIP_LIBRARY
  NAMES GeoIP libGeoIP-1
  HINTS
    "${GEOIP_LIBDIR}"
    "${GEOIP_ROOT}"
  PATH_SUFFIXES lib
)

# handle the QUIETLY and REQUIRED arguments and set GEOIP_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GEOIP DEFAULT_MSG GEOIP_LIBRARY GEOIP_INCLUDE_DIR)

if(GEOIP_FOUND)
  set(GEOIP_LIBRARIES ${GEOIP_LIBRARY})
  set(GEOIP_INCLUDE_DIRS ${GEOIP_INCLUDE_DIR})
endif()

mark_as_advanced(GEOIP_LIBRARIES GEOIP_INCLUDE_DIRS)
