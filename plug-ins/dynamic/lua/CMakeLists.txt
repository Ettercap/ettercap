include(ExternalProject)
set(plugin_name dynamic_lua)

SET(luajit_RELEASE 2.0.0-beta10)
SET(luajit_name luajit-${luajit_RELEASE}-${CMAKE_BUILD_TYPE})
SET(luajit_source ${CMAKE_CURRENT_SOURCE_DIR}/external/LuaJIT-${luajit_RELEASE}.tar.gz)
SET(luajit_build_wrapper_in ${CMAKE_CURRENT_SOURCE_DIR}/external/luajit_build_wrapper.sh.in)
SET(luajit_install_wrapper_in ${CMAKE_CURRENT_SOURCE_DIR}/external/luajit_install_wrapper.sh.in)
SET(luajit_prefix ${CMAKE_CURRENT_BINARY_DIR}/${luajit_name}_usr)
SET(luajit_build ${CMAKE_CURRENT_BINARY_DIR}/${luajit_name}_build)
SET(luajit_build_wrapper ${CMAKE_CURRENT_BINARY_DIR}/luajit_build_wrapper.sh)
SET(luajit_install_wrapper ${CMAKE_CURRENT_BINARY_DIR}/luajit_install_wrapper.sh)

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

IF(${CMAKE_BUILD_TYPE} STREQUAL Debug)
  SET(EXPORT_CCDEBUG "-g")
  # Explicitly disable CCOPT, as we do not want fomit-frame-pointer 
  # conflicting with debuggy stuff.
  SET(EXPORT_DISABLE_CCOPT CCOPT=)
  SET(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_DEBUG}")
ELSEIF(${CMAKE_BUILD_TYPE} STREQUAL Release)
  SET(EXPORT_CCDEBUG "")
  SET(EXPORT_C_FLAGS "${EXPORT_C_FLAGS} ${CMAKE_C_FLAGS_RELEASE}")
ENDIF(${CMAKE_BUILD_TYPE} STREQUAL Debug)

SET(EXPORT_BUILDMODE static)
SET(EXPORT_PREFIX ${luajit_prefix})
CONFIGURE_FILE(${luajit_build_wrapper_in} ${luajit_build_wrapper} @ONLY)
CONFIGURE_FILE(${luajit_install_wrapper_in} ${luajit_install_wrapper} @ONLY)

ExternalProject_Add(
    ${luajit_name}
    URL ${luajit_source}
    BUILD_IN_SOURCE 1
    SOURCE_DIR ${luajit_build}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND sh ${luajit_build_wrapper}
    INSTALL_COMMAND sh ${luajit_install_wrapper}
    UPDATE_COMMAND ""
)



SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
INCLUDE_DIRECTORIES(${luajit_prefix}/include/luajit-2.0 ${CMAKE_CURRENT_BINARY_DIR})
SET(LUAJIT2_STATIC_LIB ${luajit_prefix}/lib/libluajit-5.1.a)

add_library(luajit2_static STATIC IMPORTED)
set_property(TARGET luajit2_static PROPERTY
  IMPORTED_LOCATION ${LUAJIT2_STATIC_LIB})

# Our primary target.
add_library(${plugin_name} MODULE lua.c)
add_dependencies(${plugin_name} ${luajit_name})

# luajit2 will be statically linked into our plugin.
# We also have to dynamically link to libm (math), since luajit depends on it. 
target_link_libraries(${plugin_name} ettercap luajit2_static -lm)
set_target_properties(${plugin_name} PROPERTIES PREFIX "ec_")

install(TARGETS
          ${plugin_name} 
        LIBRARY DESTINATION ${INSTALL_LIBDIR}/ettercap/
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)
