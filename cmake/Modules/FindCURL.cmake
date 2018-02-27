# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL licnse.
#

# Look for the header file
find_path(CURL_INCLUDE_DIR NAMES curl/curl.h)
mark_as_advanced(CURL_INCLUDE_DIR)

# Look for the library.
find_library(CURL_LIBRARY NAMES
    curl
  # Windows MSVC prebuilts:
    curllib
    libcurl_imp
    curllib_static
)
mark_as_advanced(CURL_LIBRARY)

# Make sure we've got an include dir.
if(NOT CURL_INCLUDE_DIR)
  if(CURL_FIND_REQUIRED AND NOT CURL_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find CURL include directory.")
  endif()
  return()
endif()

if(NOT CURL_LIBRARY)
  if(CURL_FIND_REQUIRED AND NOT CURL_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find CURL library.")
  endif()
  return()
endif()

if(CURL_FIND_VERSION)
  # Try to find the version number.
  foreach(_curl_version_header curlver.h curl.h)
    if(EXISTS "${CURL_INCLUDE_DIR}/curl/${_curl_version_header}")
      file(STRINGS "${CURL_INCLUDE_DIR}/curl/${_curl_version_header}" curl_version_str
        REGEX "^#define[\t ]+LIBCURL_VERSION[\t ]+\".*\"")
      string(REGEX REPLACE "^#define[\t ]+LIBCURL_VERSION[\t ]+\"([^\"]*)\".*"
"\\1" CURL_VERSION_STRING "${curl_version_str}")
      unset(curl_version_str)
      break()
    endif()
  endforeach()

  set(CURL_FAILED_VERSION_CHECK true)

  if(CURL_FIND_VERSION_EXACT)
    if(CURL_VERSION_STRING VERSION_EQUAL CURL_FIND_VERSION)
      set(CURL_FAILED_VERSION_CHECK false)
    endif()
  else()
    if(CURL_VERSION_STRING VERSION_EQUAL   CURL_FIND_VERSION OR
      CURL_VERSION_STRING VERSION_GREATER CURL_FIND_VERSION)
      set(CURL_FAILED_VERSION_CHECK false)
    endif()
  endif()

  if(CURL_FAILED_VERSION_CHECK)
    if(CURL_FIND_REQUIRED AND NOT CURL_FIND_QUIETLY)
      if(CURL_FIND_VERSION_EXACT)
        message(FATAL_ERROR "CURL version check failed.
Version ${CURL_VERSION_STRING} was found, version ${CURL_FIND_VERSION} is needed exactly.")
      else()
        message(FATAL_ERROR "CURL version check failed.
Version ${CURL_VERSION_STRING} was found, at least version ${CURL_FIND_VERSION} is required")
      endif()
    endif()

    # If the version check fails, exit out of the module here
    return()
  endif()
endif()

#handle the QUIETLY and REQUIRED arguments and set CURL_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CURL DEFAULT_MSG CURL_LIBRARY CURL_INCLUDE_DIR)

if(CURL_FOUND)
  set(CURL_LIBRARY ${CURL_LIBRARY})
  set(CURL_INCLUDE_DIR ${CURL_INCLUDE_DIR})
  set(CURL_VERSION_STRING ${CURL_VERSION_STRING})
endif()
