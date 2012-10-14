# This will build luajit using the release that we've included with
# our distribution of ettercap.
function(setup_included_luajit)
  include(ExternalProject)
  SET(LUAJIT_VERSION 2.0.0-beta10)
  SET(LUAJIT_SOURCE_DIR ${CMAKE_SOURCE_DIR}/luajit)
  SET(LUAJIT_BUILD_ROOT ${PROJECT_BINARY_DIR}/luajit-${LUAJIT_VERSION}-${CMAKE_BUILD_TYPE})
  SET(LUAJIT_PREFIX ${LUAJIT_BUILD_ROOT}/usr)
  SET(LUAJIT_BUILD_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/luajit_build_wrapper.sh)
  SET(LUAJIT_INSTALL_WRAPPER ${CMAKE_CURRENT_BINARY_DIR}/luajit_install_wrapper.sh)

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
      included_luajit
      URL ${LUAJIT_SOURCE_DIR}/LuaJIT-${LUAJIT_VERSION}.tar.gz
      BUILD_IN_SOURCE 1
      SOURCE_DIR ${LUAJIT_BUILD_ROOT}/build
      CONFIGURE_COMMAND ""
      BUILD_COMMAND sh ${LUAJIT_BUILD_WRAPPER}
      INSTALL_COMMAND sh ${LUAJIT_INSTALL_WRAPPER}
      UPDATE_COMMAND ""
  )

  # This is the library that we're making available to everyone.
  add_library(luajit2_static STATIC IMPORTED)

  # TODO We need to work on proper discovery of the static library
  set_property(TARGET luajit2_static PROPERTY
    IMPORTED_LOCATION ${LUAJIT_PREFIX}/lib/libluajit-5.1.a)


  set(LUAJIT_LIBS luajit2_static -lm PARENT_SCOPE)
  set(LUAJIT_INCLUDE_DIR ${LUAJIT_PREFIX}/include/luajit-2.0 PARENT_SCOPE)
endfunction(setup_included_luajit)

# TODO: I'm sure someone will want to have the ability to leverage a 
#       system-provided builds of luajit, rather than using the version
#       included with our distribution of ettercap. I don't know if this is
#       the greatest idea. This should be as simple as defning a find_package
#       to attempt to look for libs/includes.

# Set up our included distribution of luajit.
setup_included_luajit()

include_directories(${LUAJIT_INCLUDE_DIR})
set(EC_LIBS ${EC_LIBS} ${LUAJIT_LIBS})

