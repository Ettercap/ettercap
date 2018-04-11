# - MACRO_ENSURE_OUT_OF_SOURCE_BUILD(<errorMessage>)
# MACRO_ENSURE_OUT_OF_SOURCE_BUILD(<errorMessage>)

# Copyright (c) 2006, Alexander Neundorf, <neundorf@kde.org>
#
# Redistribution and use is allowed according to the terms of the BSD license.
# For details see the accompanying COPYING-CMAKE-SCRIPTS file.

macro(MACRO_ENSURE_OUT_OF_SOURCE_BUILD)

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
