
set(INSTALL_LUA_ROOT ${INSTALL_DATADIR}/ettercap/lua)
set(INSTALL_LUA_INIT ${INSTALL_LUA_ROOT}/init.lua)
set(INSTALL_LUA_CORE ${INSTALL_LUA_ROOT}/core)
set(INSTALL_LUA_LIBS ${INSTALL_LUA_ROOT}/lib)
set(INSTALL_LUA_THIRD_PARTY ${INSTALL_LUA_ROOT}/third-party)
set(INSTALL_LUA_SCRIPTS ${INSTALL_LUA_ROOT}/scripts)

configure_file(ec_lua_config.h.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/include/ec_lua_config.h
)

# Take care of building our C-based stuff.

add_library(ec_lua ec_lua.c)
set_target_properties(ec_lua PROPERTIES COMPILE_FLAGS -fPIC)
target_include_directories(ec_lua
  PRIVATE
  ${CMAKE_CURRENT_BINARY_DIR}/include
  ${LUAJIT_INCLUDE_DIR}
)
add_dependencies(ec_lua luajit)

# Add our 'shared' code.
add_subdirectory(share)
