# - Try to find LibCheck
# Once done this will define
#  LIBCHECK_FOUND - System has LibCheck
#  LIBCHECK_INCLUDE_DIRS - The LibCheck include directories
#  LIBCHECK_LIBRARIES - The libraries needed to use LibCheck
#  LIBCHECK_DEFINITIONS - Compiler switches required for using LibCheck

find_package(PkgConfig)
include(FindPkgConfig)
pkg_check_modules(PC_LIBCHECK libcheck)
if(PC_LIBCHECK_FOUND)
  set(LIBCHECK_FOUND TRUE)
  set(LIBCHECK_LDFLAGS ${PC_LIBCHECK_LDFLAGS})
  set(LIBCHECK_LIBRARIES ${PC_LIBCHECK_LIBRARIES})
  set(LIBCHECK_INCLUDE_DIRS ${PC_LIBCHECK_INCLUDE_DIR})
else()
  pkg_check_modules(PC_CHECK check)
  if(PC_CHECK_FOUND)
    set(LIBCHECK_FOUND TRUE)
    set(LIBCHECK_LDFLAGS ${PC_CHECK_LDFLAGS})
    set(LIBCHECK_LIBRARIES ${PC_CHECK_LIBRARIES})
    set(LIBCHECK_INCLUDE_DIRS ${PC_CHECK_INCLUDE_DIR})
  else()
    set(LIBCHECK_DEFINITIONS ${PC_LIBCHECK_CFLAGS_OTHER})
    find_path(LIBCHECK_INCLUDE_DIR check.h
      HINTS ${PC_LIBCHECK_INCLUDEDIR} ${PC_LIBCHECK_INCLUDE_DIRS})

    find_library(LIBCHECK_LIBRARY NAMES check libcheck
      HINTS ${PC_LIBCHECK_LIBDIR} ${PC_LIBCHECK_LIBRARY_DIRS})

    if(LIBCHECK_LIBRARY_FOUND)
      set(LIBCHECK_FOUND TRUE)
      set(LIBCHECK_LIBRARIES ${LIBCHECK_LIBRARY})
    else()
      include(FindPackageHandleStandardArgs)
      # handle the QUIETLY and REQUIRED arguments and set LIBCHECK_FOUND to TRUE
      # if all listed variables are TRUE
      find_package_handle_standard_args(LIBCHECK DEFAULT_MSG
                                      LIBCHECK_LIBRARY LIBCHECK_INCLUDE_DIR)
      if(LIBCHECK_FOUND)
        set(LIBCHECK_LIBRARIES ${LIBCHECK_LIBRARY})
        set(LIBCHECK_INCLUDE_DIRS ${LIBCHECK_INCLUDE_DIR})
      endif()
    endif()
  endif()
endif()
mark_as_advanced(LIBCHECK_INCLUDE_DIR LIBCHECK_LIBRARY)
