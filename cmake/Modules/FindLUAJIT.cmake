# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL licnse.
#

# Look for the header file
find_path(LUAJIT_INCLUDE_DIR NAMES luajit.h PATH_SUFFIXES luajit-2.1 luajit-2.0 luajit)
mark_as_advanced(LUAJIT_INCLUDE_DIR)

#Look for the library
find_library(LUAJIT_LIBRARY NAMES luajit-5.1)
mark_as_advanced(LUAJIT_LIBRARY)

# Make sure we've got an include dir.
if(NOT LUAJIT_INCLUDE_DIR)
  if(LUAJIT_FIND_REQUIRED AND NOT LUAJIT_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find LUAJIT include directory.")
  endif()
  return()
endif()

if(NOT LUAJIT_LIBRARY)
  if(LUAJIT_FIND_REQUIRED AND NOT LUAJIT_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find LUAJIT library.")
  endif()
  return()
endif()

#=============================================================
# _LUAJIT_GET_VERSION
# Internal function to parse the version number in luajit.h
#   _OUT_version = The version number
#   _luajit_hdr = Header file to parse
#=============================================================
function(_LUAJIT_GET_VERSION _OUT_version _luajit_hdr)
  file(READ ${_luajit_hdr} _contents)
  if(_contents)
    # Example: #define LUAJIT_VERSION_NUM      20000  /* Version 2.0.0 = 02.00.00. */
    string(REGEX REPLACE ".*#define LUAJIT_VERSION_NUM[ \t]+([0-9]+)([0-9][0-9])([0-9][0-9])[^0-9].*"
"\\1.\\2.\\3" ${_OUT_version} "${_contents}")

    if(NOT ${_OUT_version} MATCHES "[0-9.]+")
      message(FATAL_ERROR "Version parsing failed for LUAJIT_VERSION!")
    endif()

    set(${_OUT_version} ${${_OUT_version}} PARENT_SCOPE)
  else()
    message(FATAL_ERROR "Include file ${_luajit_hdr} does not exist")
  endif()
endfunction()

if(LUAJIT_FIND_VERSION)
  set(LUAJIT_FAILED_VERSION_CHECK true)
  _luajit_get_version(LUAJIT_VERSION ${LUAJIT_INCLUDE_DIR}/luajit.h)

  if(LUAJIT_FIND_VERSION_EXACT)
    if(LUAJIT_VERSION VERSION_EQUAL LUAJIT_FIND_VERSION)
      set(LUAJIT_FAILED_VERSION_CHECK false)
    endif()
  else()
  if(LUAJIT_VERSION VERSION_EQUAL   LUAJIT_FIND_VERSION OR
    LUAJIT_VERSION VERSION_GREATER LUAJIT_FIND_VERSION)
    set(LUAJIT_FAILED_VERSION_CHECK false)
  endif()
  endif()

  if(LUAJIT_FAILED_VERSION_CHECK)
    if(LUAJIT_FIND_REQUIRED AND NOT LUAJIT_FIND_QUIETLY)
      if(LUAJIT_FIND_VERSION_EXACT)
        message(FATAL_ERROR "LUAJIT version check failed.
Version ${LUAJIT_VERSION} was found, version ${LUAJIT_FIND_VERSION} is needed exactly.")
      else()
        message(FATAL_ERROR "LUAJIT version check failed.
Version ${LUAJIT_VERSION} was found, at least version ${LUAJIT_FIND_VERSION} is required")
      endif()
    endif()

    # If the version check fails, exit out of the module here
    return()
  endif()

endif()

#handle the QUIETLY and REQUIRED arguments and set LUAJIT_FOUND to TRUE if
# all listed variables are TRUE
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LUAJIT DEFAULT_MSG LUAJIT_LIBRARY LUAJIT_INCLUDE_DIR)

if(LUAJIT_FOUND)
  set(LUAJIT_LIBRARY ${LUAJIT_LIBRARY})
  set(LUAJIT_INCLUDE_DIR ${LUAJIT_INCLUDE_DIR})
  set(LUAJIT_VERSION ${LUAJIT_VERSION})
endif()
