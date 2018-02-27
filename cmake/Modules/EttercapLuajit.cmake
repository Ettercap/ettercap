# Sets the variables:
#       LUAJIT_FOUND
#       LUAJIT_VERSION
#       LUAJIT_LIBRARY
#       LUAJIT_INCLUDE_DIR
#
# Creates target:
#       luajit


add_custom_target(luajit)

if(SYSTEM_LUAJIT)
  find_package(LUAJIT 2.0.0)

  if(NOT LUAJIT_FOUND)
    message(STATUS "Couldn't find a suitable system-provided version of LuaJIT")
  endif()
endif()

# Only go into bundled stuff if it's enabled and we haven't found it already.
if(BUNDLED_LUAJIT AND (NOT LUAJIT_FOUND))
  message(STATUS "Using bundled version of LUAJIT")
  add_subdirectory(bundled_deps/luajit EXCLUDE_FROM_ALL)
  add_dependencies(luajit bundled_luajit)
  add_dependencies(bundled bundled_luajit)
endif()

if(NOT LUAJIT_FOUND)
  message(FATAL_ERROR "Could not find LUAJIT!")
endif()
