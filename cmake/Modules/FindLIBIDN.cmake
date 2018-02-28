# - Try to find LIBIDN
# Find LIBIDN headers, libraries and the answer to all questions.
#
#  LIBIDN_FOUND               True if libidn got found
#  LIBIDN_INCLUDE_DIR        Location of libidn headers
#  LIBIDN_LIBRARIES           List of libaries to use libidn
#
# Copyright (c) 2009 Nigmatullin Ruslan <euroelessar@gmail.com>
#
#  Redistribution and use is allowed according to the terms of the New
#  BSD license.
#  For details see the accompanying COPYING-CMAKE-SCRIPTS file.
#

if(WIN32)
  find_path(LIBIDN_INCLUDE_DIR stringprep.h $ENV{INCLUDE})
  find_library(LIBIDN_LIBRARIES libidn $ENV{LIB})
else()
  find_path(LIBIDN_INCLUDE_DIR stringprep.h)
  find_library(LIBIDN_LIBRARIES idn)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBIDN DEFAULT_MSG LIBIDN_LIBRARIES LIBIDN_INCLUDE_DIR)

if(LIBIDN_FOUND)
  set(LIBIDN_LIBRARY ${LIBIDN_LIBRARIES})
  set(LIBIDN_INCLUDE_DIRS ${LIBIDN_INCLUDE_DIR})
endif()

mark_as_advanced(LIBIDN_LIBRARIES LIBIDN_INCLUDE_DIRS)
