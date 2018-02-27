# - Try to find LibCheck
# Once done this will define
#  LIBCHECK_FOUND - System has LibCheck
#  LIBCHECK_INCLUDE_DIRS - The LibCheck include directories
#  LIBCHECK_LIBRARIES - The libraries needed to use LibCheck
#  LIBCHECK_DEFINITIONS - Compiler switches required for using LibCheck

find_package(PkgConfig)
include(FindPkgConfig)
pkg_check_modules(PC_LIBCHECK libcheck)
pkg_check_modules(PC_CHECK check)
set(LIBCHECK_DEFINITIONS ${PC_LIBCHECK_CFLAGS_OTHER})
find_path(LIBCHECK_INCLUDE_DIR check.h
  HINTS ${PC_LIBCHECK_INCLUDEDIR} ${PC_LIBCHECK_INCLUDE_DIRS})

find_library(LIBCHECK_LIBRARY NAMES check libcheck
  HINTS ${PC_LIBCHECK_LIBDIR} ${PC_LIBCHECK_LIBRARY_DIRS})


include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set LIBCHECK_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(LIBCHECK DEFAULT_MSG
                                  LIBCHECK_LIBRARY LIBCHECK_INCLUDE_DIR)
if(LIBCHECK_FOUND)
  set(LIBCHECK_LDFLAGS ${PC_CHECK_LIBRARIES} ${PC_LIBCHECK_LIBRARIES} ${PC_CHECK_LDFLAGS} ${PC_LIBCHECK_LDFLGAS})
  set(LIBCHECK_LIBRARIES ${LIBCHECK_LIBRARY})
  set(LIBCHECK_INCLUDE_DIRS ${LIBCHECK_INCLUDE_DIR})
endif()
mark_as_advanced(LIBCHECK_INCLUDE_DIR LIBCHECK_LIBRARY)
