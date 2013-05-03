# This file provides the 'bundled_check' target.

# This will build check using the release that we've included with
# our distribution of ettercap.
include(ExternalProject)
SET(CHECK_VERSION 0.9.10)
SET(CHECK_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
SET(CHECK_TARGET bundled-check-${CHECK_VERSION}-${CMAKE_BUILD_TYPE})
SET(CHECK_BUILD_ROOT ${CMAKE_CURRENT_BINARY_DIR}/${CHECK_TARGET})
SET(CHECK_CONFIGURE_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/check_configure_wrapper.sh)
SET(CHECK_BUILD_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/check_build_wrapper.sh)
SET(CHECK_INSTALL_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/check_install_wrapper.sh)

SET(CHECK_PREFIX ${CHECK_BUILD_ROOT}/usr)
SET(CHECK_LIB_DIR ${CHECK_PREFIX}/lib)
SET(CHECK_INCLUDE_DIR ${CHECK_PREFIX}/include)
set(CHECK_LIBRARY ${CHECK_LIB_DIR}/${CMAKE_SHARED_LIBRARY_PREFIX}check${CMAKE_SHARED_LIBRARY_SUFFIX})  

# Configure the Makefile wrapper. The purpose of this wrapper is to set up
# the environment for building check. ExternalProject_Add doesn't 
# support setting up any sort of environment, nor does it handle arguments to
# BUILD_COMMAND (and others) that contain double-quotes. According to 
# the CMake folks, this is the way to do things.
#  ref: http://www.cmake.org/pipermail/cmake/2010-April/036566.html
# 
SET(EXPORT_CC ${CMAKE_C_COMPILER})

# -fPIC is required so that we can link in our static library, properly.
# Add the cmake env cflags and all that jazz so we can inherit architectures
# and the like.
SET(EXPORT_C_FLAGS ${CMAKE_C_FLAGS} -fPIC)

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  SET(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_DEBUG}")
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
  SET(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE}")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")

SET(EXPORT_PREFIX ${CHECK_PREFIX})

CONFIGURE_FILE(${CHECK_SOURCE_DIR}/check_configure_wrapper.sh.in 
  ${CHECK_CONFIGURE_WRAPPER} @ONLY)
CONFIGURE_FILE(${CHECK_SOURCE_DIR}/check_build_wrapper.sh.in 
  ${CHECK_BUILD_WRAPPER} @ONLY)
CONFIGURE_FILE(${CHECK_SOURCE_DIR}/check_install_wrapper.sh.in 
  ${CHECK_INSTALL_WRAPPER} @ONLY)

#########################

ExternalProject_Add(
  ${CHECK_TARGET}
  URL ${CHECK_SOURCE_DIR}/check-${CHECK_VERSION}.tar.gz
  BUILD_IN_SOURCE 1
  SOURCE_DIR ${CHECK_BUILD_ROOT}/build
  CONFIGURE_COMMAND sh ${CHECK_CONFIGURE_WRAPPER}
  BUILD_COMMAND sh ${CHECK_BUILD_WRAPPER}
  INSTALL_COMMAND sh ${CHECK_INSTALL_WRAPPER}
  UPDATE_COMMAND ""
  )

# Now export our variables to our parent's scope.
set(CHECK_VERSION ${CHECK_VERSION} PARENT_SCOPE)
set(CHECK_LIBRARY ${CHECK_LIBRARY} PARENT_SCOPE)
set(CHECK_INCLUDE_DIR ${CHECK_INCLUDE_DIR} PARENT_SCOPE)
set(CHECK_FOUND TRUE PARENT_SCOPE)
add_custom_target(bundled_check)
add_dependencies(bundled_check ${CHECK_TARGET})
