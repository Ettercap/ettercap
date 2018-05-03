# Copyright 2013-2018 Ettercap Development Team.
#
# Distributed under the GPL.
#

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_search_module(PC_LIBNET QUIET IMPORTED_TARGET libnet net)
elseif(NOT MSVC)
  find_program(LIBNET_CONFIG libnet-config)

  if(LIBNET_CONFIG)
    # First, get the include directory.
    execute_process(COMMAND sh "${LIBNET_CONFIG}" "--cflags"
      RESULT_VARIABLE LIBNET_CONFIG_RESULT
      OUTPUT_VARIABLE LIBNET_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(LIBNET_CONFIG_RESULT EQUAL 0)
      string(REGEX REPLACE "-I" ""
        LIBNET_CONFIG_INCLUDE_DIRS
        ${LIBNET_CONFIG_OUTPUT}
      )
    endif()

    # Get all libraries and their library directory.
    execute_process(COMMAND ${_shell} "${LIBNET_CONFIG}" "--libs"
      RESULT_VARIABLE LIBNET_CONFIG_RESULT
      OUTPUT_VARIABLE LIBNET_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(LIBNET_CONFIG_RESULT EQUAL 0)
      string(REGEX REPLACE "-l[lL]?[iI]?[bB]?net" ""
        LIBNET_CONFIG_OUTPUT
        ${LIBNET_CONFIG_OUTPUT}
      )
      separate_arguments(LIBNET_CONFIG_LDFLAGS
        UNIX_COMMAND
        ${LIBNET_CONFIG_OUTPUT}
      )
    endif()

    # Get preprocessor definitions.
    execute_process(COMMAND ${_shell} "${LIBNET_CONFIG}" "--defines"
      RESULT_VARIABLE LIBNET_CONFIG_RESULT
      OUTPUT_VARIABLE LIBNET_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(LIBNET_CONFIG_RESULT EQUAL 0)
      set(LIBNET_CONFIG_DEFINITIONS ${LIBNET_CONFIG_OUTPUT})
      message(STATUS "LIBNET_CONFIG_DEFINITIONS: ${LIBNET_CONFIG_DEFINITIONS}")
    endif()

    # Get install prefix.
    execute_process(COMMAND ${_shell} "${LIBNET_CONFIG}" "--prefix"
      RESULT_VARIABLE LIBNET_CONFIG_RESULT
      OUTPUT_VARIABLE LIBNET_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(LIBNET_CONFIG_RESULT EQUAL 0)
      list(APPEND CMAKE_FIND_ROOT_PATH ${LIBNET_CONFIG_OUTPUT})
      set(LIBNET_CONFIG_PREFIX ${LIBNET_CONFIG_OUTPUT})
    endif()

    # Get version string
    execute_process(COMMAND ${_shell} "${LIBNET_CONFIG}" "--version"
      RESULT_VARIABLE LIBNET_CONFIG_RESULT
      OUTPUT_VARIABLE LIBNET_CONFIG_OUTPUT
      OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    if(LIBNET_CONFIG_RESULT EQUAL 0)
      set(LIBNET_CONFIG_VERSION ${LIBNET_CONFIG_OUTPUT})
    endif()

  endif()
endif()

# Look for the header file
find_path(LIBNET_INCLUDE_DIR
  DOC "The directory containing libnet.h"
  NAMES libnet.h
  PATHS
    ${PC_LIBNET_INCLUDE_DIRS}
    ${PC_LIBNET_INCLUDEDIR}
    ${LIBNET_CONFIG_INCLUDE_DIRS}
  PATH_SUFFIXES libnet)

#Look for the library
find_library(LIBNET_LIBRARY
  DOC "The libnet library"
  NAMES net libnet libnet-static
  PATHS ${PC_LIBNET_LIBRARY_DIRS})

if(PC_LIBNET_VERSION)
  set(LIBNET_VERSION ${PC_LIBNET_VERSION})
elseif(LIBNET_CONFIG_VERSION)
  set(LIBNET_VERSION ${LIBNET_CONFIG_VERSION})
else()
  if(LIBNET_INCLUDE_DIR)
  # Get '#define LIBNET_VERSION X.X.X...'
    file(STRINGS ${LIBNET_INCLUDE_DIR}/libnet.h LIBNET_HEADER_DUMP
      REGEX "^#[d].*([0-9]+.)"
    )

    string(REGEX MATCH "([0-9]+.)([0-9]+[.]*)([0-9]*)"
      LIBNET_VERSION
      "${LIBNET_HEADER_DUMP}"
    )

    string(REGEX MATCHALL "([0-9]+)" LIBNET_VERLIST ${LIBNET_VERSION})
    list(GET LIBNET_VERLIST 0 LIBNET_VERSION_MAJOR)
    list(GET LIBNET_VERLIST 1 LIBNET_VERSION_MINOR)
    list(GET LIBNET_VERLIST 2 LIBNET_VERSION_PATCH) # unused
  endif()
endif()

# Handle the QUIETLY and REQUIRED arguments and set LIBNET_FOUND to TRUE if
# all listed variables are TRUE.
include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBNET
  REQUIRED_VARS
    LIBNET_LIBRARY
    LIBNET_INCLUDE_DIR
  VERSION_VAR LIBNET_VERSION
)

if(LIBNET_FOUND)
  set(LIBNET_INCLUDE_DIRS ${LIBNET_INCLUDE_DIR})
  set(LIBNET_LIBRARIES ${LIBNET_LIBRARY})

  if(PC_LIBNET_FOUND)
    set(LIBNET_LDFLAGS ${PC_LIBNET_LDFLAGS})
    set(LIBNET_DEFINITIONS ${PC_LIBNET_CFLAGS_OTHER})
  elseif(LIBNET_CONFIG)
    set(LIBNET_LDFLAGS ${LIBNET_CONFIG_LDFLAGS})
    set(LIBNET_DEFINITIONS ${LIBNET_CONFIG_DEFINITIONS})
  endif()

  if(NOT TARGET LIBNET::LIBNET)
    add_library(LIBNET::LIBNET UNKNOWN IMPORTED)
    set_target_properties(LIBNET::LIBNET PROPERTIES
      IMPORTED_LOCATION "${LIBNET_LIBRARY}"
      INTERFACE_INCLUDE_DIRECTORIES "${LIBNET_INCLUDE_DIR}"
      INTERFACE_COMPILE_DEFINITIONS "${LIBNET_DEFINITIONS}"
      INTERFACE_LINK_LIBRARIES "${LIBNET_LDFLAGS}")
  endif()
endif()

mark_as_advanced(LIBNET_LIBRARY LIBNET_INCLUDE_DIR)
