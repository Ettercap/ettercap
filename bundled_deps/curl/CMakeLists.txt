# This file provides the 'bundled_curl' target.

# This will build curl using the release that we've included with
# our distribution of ettercap.
include(ExternalProject)
set(CURL_VERSION 7.86.0)
set(CURL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(CURL_TARGET bundled-curl-${CURL_VERSION}-${CMAKE_BUILD_TYPE})
set(CURL_BUILD_ROOT ${CMAKE_CURRENT_BINARY_DIR}/${CURL_TARGET})

set(CURL_CONFIGURE_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/curl_configure_wrapper.sh)
set(CURL_BUILD_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/curl_build_wrapper.sh)
set(CURL_INSTALL_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/curl_install_wrapper.sh)

set(CURL_PREFIX ${CURL_BUILD_ROOT}/usr)
set(CURL_LIB_DIR ${CURL_PREFIX}/lib)
set(CURL_INCLUDE_DIR ${CURL_PREFIX}/include)

if(NOT OPENSSL_LIBRARIES)
  message(FATAL_ERROR "Cannot build bundled Curl without OpenSSL support enabled")
endif()

if(NOT ZLIB_LIBRARIES)
  message(FATAL_ERROR "Cannot build bundled Curl without zlib")
endif()

find_package(LIBIDN)
if(NOT LIBIDN_FOUND)
  message(FATAL_ERROR "Cannot build bundled Curl without idn")
endif()

find_package(LIBRTMP)
if(NOT LIBRTMP_FOUND)
  message(FATAL_ERROR "Cannot build bundled Curl without rtmp")
endif()

set(CMAKE_THREAD_PREFER_PTHREAD 1)
find_package(Threads REQUIRED)
if(NOT CMAKE_USE_PTHREADS_INIT)
    message(FATAL_ERROR "Cannot build bundled Curl without pthreads")
endif()

# Ensure that we include all the required stuff for linking to libcurl
set(CURL_LIBRARY ${CURL_LIB_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}curl${CMAKE_STATIC_LIBRARY_SUFFIX}
  ${OPENSSL_LIBRARIES}
  ${ZLIB_LIBRARIES}
  ${LIBIDN_LIBRARIES}
  ${RTMP_LIBRARIES}
  )

#Figure out the parent directory for our openssl installation.
get_filename_component(OPENSSL_ROOT_PATH ${OPENSSL_INCLUDE_DIR} PATH)

set(EXPORT_CC ${CMAKE_C_COMPILER})

# -fPIC is required so that we can link in our static library, properly.
# Add the cmake env cflags and all that jazz so we can inherit architectures
# and the like.
set(EXPORT_C_FLAGS ${CMAKE_C_FLAGS} -fPIC)

set(EXPORT_LD_FLAGS ${CMAKE_THREAD_LIBS_INIT})

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_DEBUG}")
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
  set(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE}")
endif()

set(EXPORT_PREFIX ${CURL_PREFIX})

# Enable/Disable IPV6
set(EXPORT_IPV6_FLAGS --disable-ipv6)
if(ENABLE_IPV6)
  set(EXPORT_IPV6_FLAGS --enable-ipv6)
endif()

configure_file(${CURL_SOURCE_DIR}/curl_configure_wrapper.sh.in
  ${CURL_CONFIGURE_WRAPPER} @ONLY)
configure_file(${CURL_SOURCE_DIR}/curl_build_wrapper.sh.in
  ${CURL_BUILD_WRAPPER} @ONLY)
configure_file(${CURL_SOURCE_DIR}/curl_install_wrapper.sh.in
  ${CURL_INSTALL_WRAPPER} @ONLY)

#########################

externalproject_add(
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
