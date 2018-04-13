# EttercapMacrosAndFunctions.cmake - -some text to explain this file here -

# ensure_out_of_source_build() macro
# Enforce an out-of-source build
#
# Copyright (c) 2006, Alexander Neundorf, <neundorf@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

macro(ensure_out_of_source_build)
  string(COMPARE EQUAL "${CMAKE_SOURCE_DIR}" "${CMAKE_BINARY_DIR}" _insource)
  if(_insource)
    message(SEND_ERROR "${PROJECT_NAME} requires an out of source build.
Please create a separate build directory and run \
'cmake /path/to/${PROJECT_NAME} [options]' there.")
    message(FATAL_ERROR
"Remove the file CMakeCache.txt in ${CMAKE_SOURCE_DIR} first."
    )
  endif()
endmacro()

# check_and_add_compiler_option macro
# Tests whether a compiler option works and adds it if it does.
#
# Note: I originally borrowed this macro from The TCPdump Group,
# but have edited it quite a bit ever since to suite our setup.
#
#    usage:
#         check_and_add_compiler_option(<compilerOption>)
#
include(CheckCCompilerFlag)
macro(check_and_add_compiler_option _option)
  message(STATUS "Checking C compiler flag ${_option}")
  string(REPLACE "=" "-" _temp_option_variable ${_option})
  string(REGEX REPLACE "^-" "" _option_variable ${_temp_option_variable})
  check_c_compiler_flag("${_option}" ${_option_variable})
    string(TOUPPER _${CMAKE_BUILD_TYPE} _underscore_cmake_build_type_uppercase)
    if("${${_option_variable}}" AND CMAKE_BUILD_TYPE)
      set(CMAKE_C_FLAGS${_underscore_cmake_build_type_uppercase}
        "${CMAKE_C_FLAGS${_underscore_cmake_build_type_uppercase}} ${_option}"
      )
    elseif("${${_option_variable}}" AND CMAKE_CONFIGURATION_TYPES)
      set(CMAKE_C_FLAGS_DEBUG
        "${CMAKE_C_FLAGS_DEBUG} ${_option}"
      )
    endif()
endmacro()

# XXX - add almost all var in here
# mark_as_advanced(_underscore_cmake_build_type_uppercase)
