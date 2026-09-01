# - FindGTK4.cmake
# Locate GTK4 and (optionally) libadwaita via pkg-config.
#
# Unlike FindGTK2/FindGTK3, which hand-roll a search over every transitive
# dependency, GTK4 has always shipped a reliable pkg-config file and is
# pkg-config-first on every platform it supports -- including MSYS2 and
# vcpkg on Windows.  So we simply ask pkg-config.
#
# The following variables are defined for your use:
#
#   GTK4_FOUND          - Was GTK4 found?
#   GTK4_INCLUDE_DIRS   - All include directories
#   GTK4_LIBRARIES      - All libraries
#   GTK4_LIBRARY_DIRS   - All library search paths
#   GTK4_CFLAGS_OTHER   - Additional compiler flags
#   GTK4_VERSION        - The version of GTK4 found (x.y.z)
#   GTK4_MAJOR_VERSION  - The major version of GTK4
#   GTK4_MINOR_VERSION  - The minor version of GTK4
#   GTK4_PATCH_VERSION  - The patch version of GTK4
#
#   ADWAITA_FOUND       - Was libadwaita found?
#   ADWAITA_VERSION     - The version of libadwaita found
#
# Components:
#
#   gtk       - GTK4 itself (implied when no component is given)
#   adwaita   - libadwaita-1, GNOME's platform library
#
# Example:
#
#   find_package(GTK4 4.10 REQUIRED gtk adwaita)
#   if(GTK4_FOUND)
#     include_directories(${GTK4_INCLUDE_DIRS})
#     target_link_libraries(mygui ${GTK4_LIBRARIES})
#   endif()
#
#=============================================================================
# Copyright 2026 Ettercap Development Team <info@ettercap-project.org>
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file Copyright.txt for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================

find_package(PkgConfig QUIET)

if(NOT PKG_CONFIG_FOUND)
  if(GTK4_FIND_REQUIRED)
    message(FATAL_ERROR
      "pkg-config is required to locate GTK4 but was not found.")
  endif()
  set(GTK4_FOUND FALSE)
  return()
endif()

if(NOT GTK4_FIND_COMPONENTS)
  # Assume they only want GTK itself.
  set(GTK4_FIND_COMPONENTS gtk)
endif()

set(GTK4_INCLUDE_DIRS)
set(GTK4_LIBRARIES)
set(GTK4_LIBRARY_DIRS)
set(GTK4_CFLAGS_OTHER)

# The `gtk` component is mandatory even if the caller forgot to list it --
# libadwaita on its own is not something we can build against.
list(APPEND GTK4_FIND_COMPONENTS gtk)
list(REMOVE_DUPLICATES GTK4_FIND_COMPONENTS)

set(_gtk4_missing_required)

foreach(_gtk4_component ${GTK4_FIND_COMPONENTS})
  if(_gtk4_component STREQUAL "gtk")
    set(_gtk4_module "gtk4")
    set(_gtk4_prefix "GTK4_PC")
  elseif(_gtk4_component STREQUAL "adwaita")
    set(_gtk4_module "libadwaita-1")
    set(_gtk4_prefix "ADWAITA_PC")
  else()
    message(FATAL_ERROR "Unknown GTK4 component: ${_gtk4_component}")
  endif()

  pkg_check_modules(${_gtk4_prefix} QUIET ${_gtk4_module})

  if(${_gtk4_prefix}_FOUND)
    list(APPEND GTK4_INCLUDE_DIRS ${${_gtk4_prefix}_INCLUDE_DIRS})
    list(APPEND GTK4_LIBRARIES    ${${_gtk4_prefix}_LIBRARIES})
    list(APPEND GTK4_LIBRARY_DIRS ${${_gtk4_prefix}_LIBRARY_DIRS})
    list(APPEND GTK4_CFLAGS_OTHER ${${_gtk4_prefix}_CFLAGS_OTHER})
  else()
    # An unfound optional component is not fatal; the caller inspects
    # ADWAITA_FOUND and degrades gracefully.
    if(GTK4_FIND_REQUIRED_${_gtk4_component} OR _gtk4_component STREQUAL "gtk")
      list(APPEND _gtk4_missing_required ${_gtk4_module})
    endif()
  endif()
endforeach()

if(GTK4_PC_FOUND)
  set(GTK4_VERSION ${GTK4_PC_VERSION})
  string(REPLACE "." ";" _gtk4_version_list "${GTK4_VERSION}")
  list(GET _gtk4_version_list 0 GTK4_MAJOR_VERSION)
  list(GET _gtk4_version_list 1 GTK4_MINOR_VERSION)
  list(GET _gtk4_version_list 2 GTK4_PATCH_VERSION)
  unset(_gtk4_version_list)
endif()

if(ADWAITA_PC_FOUND)
  set(ADWAITA_FOUND TRUE)
  set(ADWAITA_VERSION ${ADWAITA_PC_VERSION})
else()
  set(ADWAITA_FOUND FALSE)
endif()

if(GTK4_INCLUDE_DIRS)
  list(REMOVE_DUPLICATES GTK4_INCLUDE_DIRS)
endif()
if(GTK4_LIBRARIES)
  list(REMOVE_DUPLICATES GTK4_LIBRARIES)
endif()
if(GTK4_LIBRARY_DIRS)
  list(REMOVE_DUPLICATES GTK4_LIBRARY_DIRS)
endif()
if(GTK4_CFLAGS_OTHER)
  list(REMOVE_DUPLICATES GTK4_CFLAGS_OTHER)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GTK4
  REQUIRED_VARS GTK4_LIBRARIES GTK4_INCLUDE_DIRS
  VERSION_VAR GTK4_VERSION
  FAIL_MESSAGE
    "Could not find GTK4. Missing pkg-config module(s): ${_gtk4_missing_required}"
)

if(NOT GTK4_FOUND)
  set(GTK4_VERSION)
  set(GTK4_MAJOR_VERSION)
  set(GTK4_MINOR_VERSION)
  set(GTK4_PATCH_VERSION)
  set(GTK4_INCLUDE_DIRS)
  set(GTK4_LIBRARIES)
  set(GTK4_LIBRARY_DIRS)
  set(GTK4_CFLAGS_OTHER)
endif()

unset(_gtk4_missing_required)
unset(_gtk4_module)
unset(_gtk4_prefix)
