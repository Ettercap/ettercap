
SET(SWIG_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/ettercap_lua.c")

# Generates the lua SWIG bindings.
ADD_CUSTOM_COMMAND(
  OUTPUT ${SWIG_OUTPUT}
  COMMAND ${CMAKE_COMMAND} -E echo_append "Creating wrapper code for lua..."
  COMMAND ${SWIG_EXECUTABLE} -lua -o ${SWIG_OUTPUT} -I${EC_INCLUDE_PATH} ${SWIG_INPUT}
  COMMAND ${CMAKE_COMMAND} -E echo "Done."
  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/../*.i
  )

INCLUDE_DIRECTORIES(${LUA_INCLUDE_DIR})

add_library(dynamic_lua MODULE lua.c ${SWIG_OUTPUT})

target_link_libraries(dynamic_lua ${LUA_LIBRARIES} ettercap)
set_target_properties(dynamic_lua PROPERTIES PREFIX "ec_")

install(TARGETS
          dynamic_lua 
        LIBRARY DESTINATION ${INSTALL_LIBDIR}/ettercap/
        PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE
                    GROUP_READ GROUP_EXECUTE
                    WORLD_READ WORLD_EXECUTE)
