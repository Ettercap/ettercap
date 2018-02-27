
include_directories(. ../include ${LIBCHECK_INCLUDE_DIRS})

add_custom_target(test_verbose COMMAND ${CMAKE_CTEST_COMMAND} -V)

# Adds a test by name
macro(_t NAME)
  add_executable(test_${NAME} test_${NAME}.c)
  target_link_libraries(test_${NAME} lib_ettercap ec_interfaces
  ${LIBCHECK_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT} ${LIBCHECK_LDFLAGS})
  add_test(test_${NAME} ${CMAKE_CURRENT_BINARY_DIR}/test_${NAME})
endmacro()

_t(ec_decode)

