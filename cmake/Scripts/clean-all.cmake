
# The helps us make sure that the build directory is *really* clean.

set(cmake_generated ${CMAKE_BINARY_DIR}/CMakeCache.txt
                    ${CMAKE_BINARY_DIR}/cmake_install.cmake
                    ${CMAKE_BINARY_DIR}/Makefile
                    ${CMAKE_BINARY_DIR}/CMakeFiles
                    ${CMAKE_BINARY_DIR}/cmake_uninstall.cmake
                    ${CMAKE_BINARY_DIR}/CTestTestfile.cmake
                    ${CMAKE_BINARY_DIR}/install_manifest.txt
                    ${CMAKE_BINARY_DIR}/desktop/
                    ${CMAKE_BINARY_DIR}/include/
                    ${CMAKE_BINARY_DIR}/man/
                    ${CMAKE_BINARY_DIR}/plug-ins/
                    ${CMAKE_BINARY_DIR}/share/
                    ${CMAKE_BINARY_DIR}/src/
                    ${CMAKE_BINARY_DIR}/tests/
                    ${CMAKE_BINARY_DIR}/utils/
                    ${CMAKE_BINARY_DIR}/Testing/
                    ${CMAKE_BINARY_DIR}/AUTHORS
                    ${CMAKE_BINARY_DIR}/LICENSE
)

foreach(file ${cmake_generated})

  if(EXISTS ${file})
    file(REMOVE_RECURSE ${file})
  endif()

endforeach()
