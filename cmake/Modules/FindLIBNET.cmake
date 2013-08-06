# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL licnse.
#

# Look for the header file
FIND_PATH(LIBNET_INCLUDE_DIR NAMES libnet.h)
MARK_AS_ADVANCED(LIBNET_INCLUDE_DIR)

#Look for the library
FIND_LIBRARY(LIBNET_LIBRARY NAMES
	net
	libnet
)
MARK_AS_ADVANCED(LIBNET_LIBRARY)

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
#   _OUT_version = The version number
#   _libnet_hdr = Header file to parse
#=============================================================
function(_LIBNET_GET_VERSION _OUT_version _libnet_hdr)
    file(READ ${_libnet_hdr} _contents)
    if(_contents)
      string(REGEX REPLACE ".*#define LIBNET_VERSION[ \t]+\"([0-9.rc-]+)\".*" "\\1" ${_OUT_version} "${_contents}")
        
        if(NOT ${_OUT_version} MATCHES "[0-9.rc-]+")
            message(FATAL_ERROR "Version parsing failed for LIBNET_VERSION!")
        endif()

        set(${_OUT_version} ${${_OUT_version}} PARENT_SCOPE)
    else()
        message(FATAL_ERROR "Include file ${_libnet_hdr} does not exist")
    endif()
endfunction()

if(LIBNET_FIND_VERSION)
    set(LIBNET_FAILED_VERSION_CHECK true)
    _LIBNET_GET_VERSION(LIBNET_VERSION ${LIBNET_INCLUDE_DIR}/libnet.h)

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
                message(FATAL_ERROR "LIBNET version check failed.  Version ${LIBNET_VERSION} was found, version ${LIBNET_FIND_VERSION} is needed exactly.")
            else()
                message(FATAL_ERROR "LIBNET version check failed.  Version ${LIBNET_VERSION} was found, at least version ${LIBNET_FIND_VERSION} is required")
            endif()
        endif()    
        
        # If the version check fails, exit out of the module here
        return()
    endif()
        

endif(LIBNET_FIND_VERSION)

#handle the QUIETLY and REQUIRED arguments and set LIBNET_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(${CMAKE_ROOT}/Modules/FindPackageHandleStandardArgs.cmake)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBNET DEFAULT_MSG LIBNET_LIBRARY LIBNET_INCLUDE_DIR)

if(LIBNET_FOUND)
	set(LIBNET_LIBRARY ${LIBNET_LIBRARY})
	set(LIBNET_INCLUDE_DIR ${LIBNET_INCLUDE_DIR})
        set(LIBNET_VERSION ${LIBNET_VERSION})
endif(LIBNET_FOUND)
