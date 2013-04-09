# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL licnse.
#

# Look for the header file
FIND_PATH(CURL_INCLUDE_DIR NAMES curl/curl.h)
MARK_AS_ADVANCED(CURL_INCLUDE_DIR)

# Look for the library.
FIND_LIBRARY(CURL_LIBRARY NAMES 
    curl
  # Windows MSVC prebuilts:
    curllib
    libcurl_imp
    curllib_static
)
MARK_AS_ADVANCED(CURL_LIBRARY)

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
    FOREACH(_curl_version_header curlver.h curl.h)
      IF(EXISTS "${CURL_INCLUDE_DIR}/curl/${_curl_version_header}")
        FILE(STRINGS "${CURL_INCLUDE_DIR}/curl/${_curl_version_header}" curl_version_str REGEX "^#define[\t ]+LIBCURL_VERSION[\t ]+\".*\"")

        STRING(REGEX REPLACE "^#define[\t ]+LIBCURL_VERSION[\t ]+\"([^\"]*)\".*" "\\1" CURL_VERSION_STRING "${curl_version_str}")
        UNSET(curl_version_str)
        BREAK()
      ENDIF()
    ENDFOREACH(_curl_version_header)

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
                message(FATAL_ERROR "CURL version check failed.  Version ${CURL_VERSION_STRING} was found, version ${CURL_FIND_VERSION} is needed exactly.")
            else()
                message(FATAL_ERROR "CURL version check failed.  Version ${CURL_VERSION_STRING} was found, at least version ${CURL_FIND_VERSION} is required")
            endif()
        endif()    
        
        # If the version check fails, exit out of the module here
        return()
    endif()
endif(CURL_FIND_VERSION)

#handle the QUIETLY and REQUIRED arguments and set CURL_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(${CMAKE_ROOT}/Modules/FindPackageHandleStandardArgs.cmake)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(CURL DEFAULT_MSG CURL_LIBRARY CURL_INCLUDE_DIR)

if(CURL_FOUND)
	set(CURL_LIBRARY ${CURL_LIBRARY})
	set(CURL_INCLUDE_DIR ${CURL_INCLUDE_DIR})
        set(CURL_VERSION_STRING ${CURL_VERSION_STRING})
endif(CURL_FOUND)
