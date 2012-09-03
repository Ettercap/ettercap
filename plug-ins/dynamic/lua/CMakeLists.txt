include(ExternalProject)
SET(luajit_RELEASE 2.0.0-beta10)
SET(luajit_name luajit-${luajit_RELEASE})
SET(luajit_source ${CMAKE_CURRENT_SOURCE_DIR}/external/LuaJIT-${luajit_RELEASE}.tar.gz)
SET(luajit_prefix ${CMAKE_CURRENT_BINARY_DIR}/${luajit_name}_prefix)
SET(luajit_build ${CMAKE_CURRENT_BINARY_DIR}/${luajit_name}_build)
ExternalProject_Add(
    ${luajit_name}
    URL ${luajit_source}
    BUILD_IN_SOURCE 1
    SOURCE_DIR ${luajit_build}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make PREFIX=${luajit_prefix}
    INSTALL_COMMAND make install PREFIX=${luajit_prefix}
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
)


SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
INCLUDE_DIRECTORIES(${luajit_prefix}/include/luajit-2.0 ${CMAKE_CURRENT_BINARY_DIR})
SET(LUAJIT_LIBS ${luajit_prefix}/lib/libluajit-5.1.a)

add_library(dynamic_lua MODULE lua.c)
add_library( STATIC IMPORTED)
add_dependencies(dynamic_lua ${luajit_name})
target_link_libraries(dynamic_lua ettercap ${luajit_prefix}/lib/libluajit-5.1)
set_target_properties(dynamic_lua PROPERTIES PREFIX "ec_")

install(TARGETS
          dynamic_lua 
        LIBRARY DESTINATION ${INSTALL_LIBDIR}/ettercap/
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)
