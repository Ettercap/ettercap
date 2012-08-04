FIND_PACKAGE(SWIG)

IF(SWIG_FOUND)
  SET( SWIG_INPUT ${CMAKE_CURRENT_SOURCE_DIR}/ettercap.i )

  # Try to find all the stuff so that we can build LUA plugin.
  FIND_PACKAGE(Lua51)

  IF(LUA51_FOUND)
    ADD_SUBDIRECTORY(lua)
  ENDIF(LUA51_FOUND)

ENDIF(SWIG_FOUND)

