# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL licnse.
#

# Look for the header file
FIND_PATH(PCRE_INCLUDE_DIR NAMES pcre.h)
MARK_AS_ADVANCED(PCRE_INCLUDE_DIR)

# Look for the library.
FIND_LIBRARY(PCRE_LIBRARY NAMES 
    pcre
)
MARK_AS_ADVANCED(PCRE_LIBRARY)

# Make sure we've got an include dir.
if(NOT PCRE_INCLUDE_DIR)
  if(PCRE_FIND_REQUIRED AND NOT PCRE_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find PCRE include directory.")
  endif()
  return()
endif()

if(NOT PCRE_LIBRARY)
  if(PCRE_FIND_REQUIRED AND NOT PCRE_FIND_QUIETLY)
    message(FATAL_ERROR "Could not find PCRE library.")
  endif()
  return()
endif()

function(extract_version FILENAME DEFNAME VARIABLE)
  FILE(STRINGS ${FILENAME} pcre_version_str REGEX "^#define[\t ]+${DEFNAME}[\t ]+.*")
  STRING(REGEX REPLACE "^#define[\t ]+${DEFNAME}[\t ]+([0-9]+).*" "\\1" temp_var "${pcre_version_str}")
  SET(${VARIABLE} ${temp_var} PARENT_SCOPE)
endfunction()

if(PCRE_FIND_VERSION)
    # Try to find the version number.
    set(HEADER_FILE "${PCRE_INCLUDE_DIR}/pcre.h")
    IF(EXISTS ${HEADER_FILE})
      extract_version(${HEADER_FILE} PCRE_MAJOR PCRE_VERSION_STRING_MAJOR) 
      extract_version(${HEADER_FILE} PCRE_MINOR PCRE_VERSION_STRING_MINOR) 
      set(PCRE_VERSION_STRING "${PCRE_VERSION_STRING_MAJOR}.${PCRE_VERSION_STRING_MINOR}")
    ENDIF()

    set(PCRE_FAILED_VERSION_CHECK true)

    if(PCRE_FIND_VERSION_EXACT)
        if(PCRE_VERSION_STRING VERSION_EQUAL PCRE_FIND_VERSION)
            set(PCRE_FAILED_VERSION_CHECK false)
        endif()
    else()
      if(PCRE_VERSION_STRING VERSION_EQUAL   PCRE_FIND_VERSION OR
           PCRE_VERSION_STRING VERSION_GREATER PCRE_FIND_VERSION)
            set(PCRE_FAILED_VERSION_CHECK false)
        endif()
    endif()

    if(PCRE_FAILED_VERSION_CHECK)
        if(PCRE_FIND_REQUIRED AND NOT PCRE_FIND_QUIETLY)
            if(PCRE_FIND_VERSION_EXACT)
                message(FATAL_ERROR "PCRE version check failed.  Version ${PCRE_VERSION_STRING} was found, version ${PCRE_FIND_VERSION} is needed exactly.")
            else()
                message(FATAL_ERROR "PCRE version check failed.  Version ${PCRE_VERSION_STRING} was found, at least version ${PCRE_FIND_VERSION} is required")
            endif()
        endif()    
        
        # If the version check fails, exit out of the module here
        return()
    endif()
endif(PCRE_FIND_VERSION)

#handle the QUIETLY and REQUIRED arguments and set PCRE_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(${CMAKE_ROOT}/Modules/FindPackageHandleStandardArgs.cmake)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(PCRE DEFAULT_MSG PCRE_LIBRARY PCRE_INCLUDE_DIR)

if(PCRE_FOUND)
	set(PCRE_LIBRARY ${PCRE_LIBRARY})
	set(PCRE_INCLUDE_DIR ${PCRE_INCLUDE_DIR})
        set(PCRE_VERSION_STRING ${PCRE_VERSION_STRING})
endif(PCRE_FOUND)

