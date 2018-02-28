include(CheckCSourceCompiles)

macro(CHECK_VARIABLE_IN_HEADERS _SYMBOL _HEADER _RESULT)
  set(_INCLUDE_FILES)
  foreach(it ${_HEADER})
    set(_INCLUDE_FILES "${_INCLUDE_FILES}#include <${it}>\n")
  endforeach()

  set(_CHECK_PROTO_EXISTS_SOURCE_CODE "
${_INCLUDE_FILES}
void cmakeRequireSymbol(int dummy,...){(void)dummy;}
int main()
{
  int i = ${_SYMBOL};
  return 0;
}
")

  check_c_source_compiles("${_CHECK_PROTO_EXISTS_SOURCE_CODE}" ${_RESULT})

  if(${_RESULT})
    file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
    "Variable ${_SYMBOL} was found in headers\n")
  else()
    file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
    "Failed to find variable ${_SYMBOL}. Source: ${_CHECK_PROTO_EXISTS_SOURCE_CODE}\n")
  endif()
endmacro()

