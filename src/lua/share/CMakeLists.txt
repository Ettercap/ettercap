add_subdirectory(core)
add_subdirectory(lib)
add_subdirectory(scripts)
add_subdirectory(third-party)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/init.lua.in ${CMAKE_CURRENT_BINARY_DIR}/init.lua)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/init.lua DESTINATION ${INSTALL_LUA_ROOT})

