
# GLOBAL BUILD PARAMETERS
# =======================

# Global compile definitions
# --------------------------

add_definitions(-D_FORTIFY_SOURCE=2)

# Global include directories
# --------------------------

include_directories(
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/include
)

# Global linker flags
# -------------------

if(OS_DARWIN)
set(CMAKE_EXE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-Wl" CACHE STRING "" FORCE)
set(CMAKE_MODULE_LINKER_FLAGS "-Wl" CACHE STRING "" FORCE)
endif()

# Set build Type
# --------------

# XXX - move this line to EttercapOSTest.cmake
get_property(IS_MULTI_CONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

set(VALID_BUILD_TYPES "Debug, Release, RelWithDebInfo and MinSizeRel")
if(NOT CMAKE_BUILD_TYPE AND NOT "${IS_MULTI_CONFIG}")
  # On "single-configuration generators", default to the "Release" build type.
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
    "Choose the type of build, options are: ${VALID_BUILD_TYPES}." FORCE
  )
endif()

# Debug build Type
# ----------------

if(CMAKE_BUILD_TYPE STREQUAL "Debug" OR CMAKE_CONFIGURATION_TYPES)
# Set build flags for debug builds

  add_definitions(-DDEBUG)
  add_definitions(-D_DEBUG)

  # Check and add compiler options if they exist.
  # ---------------------------------------------
  #
  # You may add any kind of compiler flag to this.
  # If your compiler supports it, it will be added, if not, it will be skipped.
  check_and_add_compiler_option(-O0)
  check_and_add_compiler_option(-ggdb3)
  check_and_add_compiler_option(-Wall)
  check_and_add_compiler_option(-Wno-pointer-sign)
  check_and_add_compiler_option(-Wformat)
  check_and_add_compiler_option(-Werror=format-security)
  check_and_add_compiler_option(-Wextra)
  check_and_add_compiler_option(-Wredundant-decls)
  check_and_add_compiler_option(-W4) # MSVC only
  check_and_add_compiler_option(-Wused-but-marked-unused) # Clang/llVM only
endif()