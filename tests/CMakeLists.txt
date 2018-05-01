add_custom_target(test_verbose
  COMMAND ${CMAKE_CTEST_COMMAND}
    --interactive-debug-mode 0
    --output-on-failure
      # ${CTEST_CONFIGURATION_TYPE} is known only at ctest runtime
      # (by calling ctest -c <Configuration>), so we have to escape $
      # to delay variable substitution here.
    --build_dir ${CMAKE_CURRENT_BINARY_DIR}/\${CTEST_CONFIGURATION_TYPE}
    --build-config ${CMAKE_BUILD_TYPE}
    --extra-verbose
  COMMENT "Running Unit Tests"
  DEPENDS test_ec_decode
)

# Adds a test by name
macro(_t NAME)
  add_executable(test_${NAME} test_${NAME}.c)
  target_link_libraries(test_${NAME} lib_ettercap CHECK::CHECK)
  add_test(test_${NAME} ${CMAKE_CURRENT_BINARY_DIR}/test_${NAME})
endmacro()

_t(ec_decode)

