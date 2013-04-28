add_subdirectory(check)

include_directories(. ../include ${CHECK_INCLUDE_DIR})

add_custom_target(test_verbose COMMAND ${CMAKE_CTEST_COMMAND} -V)

# Adds a test by name
macro(_t NAME)
  add_executable(test_${NAME} test_${NAME}.c)
  add_dependencies(test_${NAME} bundled_check)
  target_link_libraries(test_${NAME} lib_ettercap ${CHECK_LIBRARY})
  add_test(test_${NAME} ${CMAKE_CURRENT_BINARY_DIR}/test_${NAME})
endmacro(_t NAME)

_t(ec_decode)

