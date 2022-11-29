# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL licnse.
#

# Look for the header file
find_path(PCRE2_INCLUDE_DIR NAMES pcre2.h)
mark_as_advanced(PCRE2_INCLUDE_DIR)

# Look for the library.
find_library(PCRE2_LIBRARY NAMES pcre2-8)
mark_as_advanced(PCRE2_LIBRARY)

# Make sure we've got an include dir.
if(NOT PCRE2_INCLUDE_DIR)
  if(PCRE2_FIND_REQUIRED AND NOT PCRE2_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find PCRE2 include directory.")
  endif()
  return()
endif()

if(NOT PCRE2_LIBRARY)
  if(PCRE2_FIND_REQUIRED AND NOT PCRE2_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find PCRE2 library.")
  endif()
  return()
endif()

function(extract_version FILENAME DEFNAME VARIABLE)
  file(STRINGS ${FILENAME} pcre_version_str REGEX "^#define[\t ]+${DEFNAME}[\t ]+.*")
  string(REGEX REPLACE "^#define[\t ]+${DEFNAME}[\t ]+([0-9]+).*" "\\1" temp_var "${pcre_version_str}")
  set(${VARIABLE} ${temp_var} PARENT_SCOPE)
endfunction()

if(PCRE2_FIND_VERSION)
  # Try to find the version number.
  set(HEADER_FILE "${PCRE2_INCLUDE_DIR}/pcre2.h")
  if(EXISTS ${HEADER_FILE})
    extract_version(${HEADER_FILE} PCRE2_MAJOR PCRE2_VERSION_STRING_MAJOR)
    extract_version(${HEADER_FILE} PCRE2_MINOR PCRE2_VERSION_STRING_MINOR)
    set(PCRE2_VERSION_STRING "${PCRE2_VERSION_STRING_MAJOR}.${PCRE2_VERSION_STRING_MINOR}")
  endif()

  set(PCRE2_FAILED_VERSION_CHECK true)

  if(PCRE2_FIND_VERSION_EXACT)
    if(PCRE2_VERSION_STRING VERSION_EQUAL PCRE2_FIND_VERSION)
      set(PCRE2_FAILED_VERSION_CHECK false)
    endif()
  else()
    if(PCRE2_VERSION_STRING VERSION_EQUAL   PCRE2_FIND_VERSION OR
      PCRE2_VERSION_STRING VERSION_GREATER PCRE2_FIND_VERSION)
      set(PCRE2_FAILED_VERSION_CHECK false)
    endif()
  endif()

  if(PCRE2_FAILED_VERSION_CHECK)
    if(PCRE2_FIND_REQUIRED AND NOT PCRE2_FIND_QUIETLY)
      if(PCRE2_FIND_VERSION_EXACT)
        message(FATAL_ERROR "PCRE2 version check failed.
Version ${PCRE2_VERSION_STRING} was found, version ${PCRE2_FIND_VERSION} is needed exactly.")
      else()
        message(FATAL_ERROR "PCRE2 version check failed.
Version ${PCRE2_VERSION_STRING} was found, at least version ${PCRE2_FIND_VERSION} is required")
      endif()
    endif()

    # If the version check fails, exit out of the module here
    return()
  endif()
endif()

#handle the QUIETLY and REQUIRED arguments and set PCRE2_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCRE2 DEFAULT_MSG PCRE2_LIBRARY PCRE2_INCLUDE_DIR)

if(PCRE2_FOUND)
  set(PCRE2_LIBRARY ${PCRE2_LIBRARY})
  set(PCRE2_INCLUDE_DIR ${PCRE2_INCLUDE_DIR})
  set(PCRE2_VERSION_STRING ${PCRE2_VERSION_STRING})
endif()

