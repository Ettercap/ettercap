# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL license.
#

# Look for the header file
find_path(LIBNET_INCLUDE_DIR
      NAMES libnet.h
      PATH_SUFFIXES libnet11 libnet-1.1)
mark_as_advanced(LIBNET_INCLUDE_DIR)

#Look for the library
find_library(LIBNET_LIBRARY
      NAMES net libnet
      PATH_SUFFIXES libnet11 libnet-1.1)
mark_as_advanced(LIBNET_LIBRARY)

# Make sure we've got an include dir.
if(NOT LIBNET_INCLUDE_DIR)
  if(LIBNET_FIND_REQUIRED AND NOT LIBNET_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find LIBNET include directory.")
  endif()
  return()
endif()

if(NOT LIBNET_LIBRARY)
  if(LIBNET_FIND_REQUIRED AND NOT LIBNET_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find LIBNET library.")
  endif()
  return()
endif()

#=============================================================
# _LIBNET_GET_VERSION
# Internal function to parse the version number in libnet.h
#   _OUT_version = The full version number
#   _OUT_version_major = The major version number only
#   _OUT_version_minor = The minor version number only
#   _libnet_hdr = Header file to parse
#=============================================================
function(_LIBNET_GET_VERSION _OUT_version _OUT_version_major _OUT_version_minor _libnet_hdr)
  file(READ ${_libnet_hdr} _contents)
  if(_contents)
    string(REGEX REPLACE ".*#define LIBNET_VERSION[ \t]+\"([0-9.a-zA-Z-]+)\".*" "\\1" ${_OUT_version} "${_contents}")

    if(NOT ${_OUT_version} MATCHES "[0-9.a-zA-Z-]+")
      message(FATAL_ERROR "Version parsing failed for LIBNET_VERSION!")
    endif()

    set(${_OUT_version} ${${_OUT_version}} PARENT_SCOPE)

    string(REGEX REPLACE "^([0-9]+)\\.[0-9]+.*" "\\1" ${_OUT_version_major} "${${_OUT_version}}")
    string(REGEX REPLACE "^[0-9]+\\.([0-9]+).*" "\\1" ${_OUT_version_minor} "${${_OUT_version}}")

      if(NOT ${_OUT_version_major} MATCHES "[0-9]+" OR NOT ${_OUT_version_minor} MATCHES "[0-9]+")
        message(FATAL_ERROR "Version parsing failed for detailed LIBNET_VERSION!:
'${_OUT_version}' '${_OUT_version_major}' '${_OUT_version_minor}'")
      endif()

    set(${_OUT_version_major} ${${_OUT_version_major}} PARENT_SCOPE)
    set(${_OUT_version_minor} ${${_OUT_version_minor}} PARENT_SCOPE)

  else()
    message(FATAL_ERROR "Include file ${_libnet_hdr} does not exist")
  endif()
endfunction()

if(LIBNET_FIND_VERSION)
  set(LIBNET_FAILED_VERSION_CHECK true)
  _libnet_get_version(LIBNET_VERSION LIBNET_VERSION_MAJOR LIBNET_VERSION_MINOR ${LIBNET_INCLUDE_DIR}/libnet.h)

  if(LIBNET_FIND_VERSION_EXACT)
    if(LIBNET_VERSION VERSION_EQUAL LIBNET_FIND_VERSION)
      set(LIBNET_FAILED_VERSION_CHECK false)
    endif()
  else()
    if(LIBNET_VERSION VERSION_EQUAL   LIBNET_FIND_VERSION OR
      LIBNET_VERSION VERSION_GREATER LIBNET_FIND_VERSION)
      set(LIBNET_FAILED_VERSION_CHECK false)
    endif()
  endif()

  if(LIBNET_FAILED_VERSION_CHECK)
    if(LIBNET_FIND_REQUIRED AND NOT LIBNET_FIND_QUIETLY)
      if(LIBNET_FIND_VERSION_EXACT)
        message(FATAL_ERROR "LIBNET version check failed.
Version ${LIBNET_VERSION} was found, version ${LIBNET_FIND_VERSION} is needed exactly.")
      else()
      message(FATAL_ERROR "LIBNET version check failed.
Version ${LIBNET_VERSION} was found, at least version ${LIBNET_FIND_VERSION} is required")
      endif()
    endif()

    # If the version check fails, exit out of the module here
    return()
  endif()

endif()

#handle the QUIETLY and REQUIRED arguments and set LIBNET_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBNET DEFAULT_MSG LIBNET_LIBRARY LIBNET_INCLUDE_DIR)

if(LIBNET_FOUND)
  set(LIBNET_LIBRARY ${LIBNET_LIBRARY})
  set(LIBNET_INCLUDE_DIR ${LIBNET_INCLUDE_DIR})
  set(LIBNET_VERSION ${LIBNET_VERSION})
  set(LIBNET_VERSION_MAJOR ${LIBNET_VERSION_MAJOR})
  set(LIBNET_VERSION_MINOR ${LIBNET_VERSION_MINOR})
endif()
