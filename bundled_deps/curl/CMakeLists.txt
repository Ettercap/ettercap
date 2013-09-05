# This file provides the 'bundled_curl' target.

# This will build curl using the release that we've included with
# our distribution of ettercap.
include(ExternalProject)
SET(CURL_VERSION 7.32.0)
SET(CURL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
SET(CURL_TARGET bundled-curl-${CURL_VERSION}-${CMAKE_BUILD_TYPE})
SET(CURL_BUILD_ROOT ${CMAKE_CURRENT_BINARY_DIR}/${CURL_TARGET})

SET(CURL_CONFIGURE_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/curl_configure_wrapper.sh)
SET(CURL_BUILD_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/curl_build_wrapper.sh)
SET(CURL_INSTALL_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/curl_install_wrapper.sh)

SET(CURL_PREFIX ${CURL_BUILD_ROOT}/usr)
SET(CURL_LIB_DIR ${CURL_PREFIX}/lib)
SET(CURL_INCLUDE_DIR ${CURL_PREFIX}/include)

if (NOT OPENSSL_LIBRARIES)
  message(FATAL_ERROR "Cannot build bundled Curl without OpenSSL support enabled (ENABLE_SSL=On)")
endif()

if (NOT ZLIB_LIBRARIES)
  message(FATAL_ERROR "Cannot build bundled Curl without zlib")
endif()

# Ensure that we include all the required stuff for linking to libcurl
SET(CURL_LIBRARY ${CURL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}curl${CMAKE_STATIC_LIBRARY_SUFFIX}
  ${OPENSSL_LIBRARIES}
  ${ZLIB_LIBRARIES}
  )  

#Figure out the parent directory for our openssl installation.
get_filename_component(OPENSSL_ROOT_PATH ${OPENSSL_INCLUDE_DIR} PATH)

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

SET(EXPORT_PREFIX ${CURL_PREFIX})

# Enable/Disable IPV6
SET(EXPORT_IPV6_FLAGS --disable-ipv6)
if(ENABLE_IPV6)
  SET(EXPORT_IPV6_FLAGS --enable-ipv6)
endif()

CONFIGURE_FILE(${CURL_SOURCE_DIR}/curl_configure_wrapper.sh.in 
  ${CURL_CONFIGURE_WRAPPER} @ONLY)
CONFIGURE_FILE(${CURL_SOURCE_DIR}/curl_build_wrapper.sh.in 
  ${CURL_BUILD_WRAPPER} @ONLY)
CONFIGURE_FILE(${CURL_SOURCE_DIR}/curl_install_wrapper.sh.in 
  ${CURL_INSTALL_WRAPPER} @ONLY)

#########################

ExternalProject_Add(
  ${CURL_TARGET}
  URL ${CURL_SOURCE_DIR}/curl-${CURL_VERSION}.tar.gz
  BUILD_IN_SOURCE 1
  SOURCE_DIR ${CURL_BUILD_ROOT}/build
  CONFIGURE_COMMAND sh ${CURL_CONFIGURE_WRAPPER}
  BUILD_COMMAND sh ${CURL_BUILD_WRAPPER}
  INSTALL_COMMAND sh ${CURL_INSTALL_WRAPPER}
  UPDATE_COMMAND ""
  )

# Now export our variables to our parent's scope.
set(CURL_VERSION_STRING ${CURL_VERSION} PARENT_SCOPE)
set(CURL_LIBRARY ${CURL_LIBRARY} PARENT_SCOPE)
set(CURL_INCLUDE_DIR ${CURL_INCLUDE_DIR} PARENT_SCOPE)
set(CURL_FOUND TRUE PARENT_SCOPE)
add_custom_target(bundled_curl)
add_dependencies(bundled_curl ${CURL_TARGET})
