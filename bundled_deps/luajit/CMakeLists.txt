include(ExternalProject)
SET(LUAJIT_VERSION 2.0.2)
SET(LUAJIT_TARGET bundled-luajit-${LUAJIT_VERSION}-${CMAKE_BUILD_TYPE})
SET(LUAJIT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
SET(LUAJIT_BUILD_ROOT ${CMAKE_CURRENT_BINARY_DIR}/${LUAJIT_TARGET})
SET(LUAJIT_BUILD_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/luajit_build_wrapper.sh)
SET(LUAJIT_INSTALL_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/luajit_install_wrapper.sh)

SET(LUAJIT_PREFIX ${LUAJIT_BUILD_ROOT}/usr)
SET(LUAJIT_LIB_DIR ${LUAJIT_PREFIX}/lib)
set(LUAJIT_INCLUDE_DIR ${LUAJIT_PREFIX}/include/luajit-2.0)

# LuaJIT requires both libm and libdl.. Let's find those.

find_library(LIB_M m)
if(NOT LIB_M)
  message(FATAL_ERROR "Could not find libm, which is required by luajit.")
endif()

find_library(LIB_DL dl)
if(NOT LIB_DL)
  message(FATAL_ERROR "Could not find libdl, which is required by luajit.")
endif()


set(LUAJIT_LIBRARY 
  ${LUAJIT_PREFIX}/lib/${CMAKE_STATIC_LIBRARY_PREFIX}luajit-5.1${CMAKE_STATIC_LIBRARY_SUFFIX}
  ${LIB_M}
  ${LIB_DL}
  )

# Configure the Makefile wrapper. The purpose of this wrapper is to set up
# the environment for building luajit. ExternalProject_Add doesn't 
# support setting up any sort of environment, nor does it handle arguments to
# BUILD_COMMAND (and others) that contain double-quotes. According to 
# the CMake folks, this is the way to do things.
#  ref: http://www.cmake.org/pipermail/cmake/2010-April/036566.html
# 
SET(EXPORT_CC ${CMAKE_C_COMPILER})

# -fPIC is required so that we can link in our static library, properly.
# Add the cmake env cflags and all that jazz so we can inherit architectures
# and the like.
SET(EXPORT_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

IF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  SET(EXPORT_CCDEBUG "-g")
  # Explicitly disable CCOPT, as we do not want fomit-frame-pointer 
  # conflicting with debuggy stuff.
  SET(EXPORT_DISABLE_CCOPT CCOPT=)
  SET(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_DEBUG}")
ELSEIF("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
  SET(EXPORT_CCDEBUG "")
  SET(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE}")
ENDIF("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")

SET(EXPORT_BUILDMODE static)
SET(EXPORT_PREFIX ${LUAJIT_PREFIX})

CONFIGURE_FILE(${LUAJIT_SOURCE_DIR}/luajit_build_wrapper.sh.in 
               ${LUAJIT_BUILD_WRAPPER} @ONLY)
CONFIGURE_FILE(${LUAJIT_SOURCE_DIR}/luajit_install_wrapper.sh.in 
               ${LUAJIT_INSTALL_WRAPPER} @ONLY)

#########################

ExternalProject_Add(
    ${LUAJIT_TARGET}
    URL ${LUAJIT_SOURCE_DIR}/LuaJIT-${LUAJIT_VERSION}.tar.gz
    BUILD_IN_SOURCE 1
    SOURCE_DIR ${LUAJIT_BUILD_ROOT}/build
    CONFIGURE_COMMAND ""
    BUILD_COMMAND sh ${LUAJIT_BUILD_WRAPPER}
    INSTALL_COMMAND sh ${LUAJIT_INSTALL_WRAPPER}
    UPDATE_COMMAND ""
)

set(LUAJIT_VERSION ${LUAJIT_VERSION} PARENT_SCOPE)
set(LUAJIT_LIBRARY ${LUAJIT_LIBRARY} PARENT_SCOPE)
set(LUAJIT_INCLUDE_DIR ${LUAJIT_INCLUDE_DIR} PARENT_SCOPE)
set(LUAJIT_FOUND TRUE PARENT_SCOPE)

add_custom_target(bundled_luajit)
add_dependencies(bundled_luajit ${LUAJIT_TARGET})
