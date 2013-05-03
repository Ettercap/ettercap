# This file provides the 'bundled_libnet' target.

# This will build libnet using the release that we've included with
# our distribution of ettercap.
include(ExternalProject)
SET(LIBNET_VERSION 1.1.6)
SET(LIBNET_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
SET(LIBNET_TARGET bundled-libnet-${LIBNET_VERSION}-${CMAKE_BUILD_TYPE})
SET(LIBNET_BUILD_ROOT ${CMAKE_CURRENT_BINARY_DIR}/${LIBNET_TARGET})
SET(LIBNET_CONFIGURE_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/libnet_configure_wrapper.sh)
SET(LIBNET_BUILD_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/libnet_build_wrapper.sh)
SET(LIBNET_INSTALL_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/libnet_install_wrapper.sh)

SET(LIBNET_PREFIX ${LIBNET_BUILD_ROOT}/usr)
SET(LIBNET_LIB_DIR ${LIBNET_PREFIX}/lib)
SET(LIBNET_INCLUDE_DIR ${LIBNET_PREFIX}/include)
set(LIBNET_LIBRARY ${LIBNET_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}net${CMAKE_STATIC_LIBRARY_SUFFIX})  

# Configure the Makefile wrapper. The purpose of this wrapper is to set up
# the environment for building libnet. ExternalProject_Add doesn't 
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

SET(EXPORT_PREFIX ${LIBNET_PREFIX})

CONFIGURE_FILE(${LIBNET_SOURCE_DIR}/libnet_configure_wrapper.sh.in 
  ${LIBNET_CONFIGURE_WRAPPER} @ONLY)
CONFIGURE_FILE(${LIBNET_SOURCE_DIR}/libnet_build_wrapper.sh.in 
  ${LIBNET_BUILD_WRAPPER} @ONLY)
CONFIGURE_FILE(${LIBNET_SOURCE_DIR}/libnet_install_wrapper.sh.in 
  ${LIBNET_INSTALL_WRAPPER} @ONLY)

#########################

ExternalProject_Add(
  ${LIBNET_TARGET}
  URL ${LIBNET_SOURCE_DIR}/libnet-${LIBNET_VERSION}.tar.gz
  BUILD_IN_SOURCE 1
  SOURCE_DIR ${LIBNET_BUILD_ROOT}/build
  CONFIGURE_COMMAND sh ${LIBNET_CONFIGURE_WRAPPER}
  BUILD_COMMAND sh ${LIBNET_BUILD_WRAPPER}
  INSTALL_COMMAND sh ${LIBNET_INSTALL_WRAPPER}
  UPDATE_COMMAND ""
  )

# Now export our variables to our parent's scope.
set(LIBNET_VERSION ${LIBNET_VERSION} PARENT_SCOPE)
set(LIBNET_LIBRARY ${LIBNET_LIBRARY} PARENT_SCOPE)
set(LIBNET_INCLUDE_DIR ${LIBNET_INCLUDE_DIR} PARENT_SCOPE)
set(LIBNET_FOUND TRUE PARENT_SCOPE)
add_custom_target(bundled_libnet)
add_dependencies(bundled_libnet ${LIBNET_TARGET})
