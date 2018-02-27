file(GLOB lua_stdlib_files "*.lua")


set(VERSION ${LUA_STDLIB_VERSION})
configure_file(std.lua.in ${CMAKE_CURRENT_BINARY_DIR}/std.lua)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/std.lua
  ${lua_stdlib_files}
  DESTINATION ${INSTALL_LUA_THIRD_PARTY})
