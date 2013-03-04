# Copyright 2013 Ettercap Development Team.
#
# Distributed under GPL licnse.
#

# Look for the header file
FIND_PATH(LIBNET_INCLUDE_DIR NAMES libnet.h)
MARK_AS_ADVANCED(LIBNET_INCLUDE_DIR)

#Look for the library
FIND_LIBRARY(LIBNET_LIBRARY NAMES
	net
	libnet
)
MARK_AS_ADVANCED(LIBNET_LIBRARY)

#handle the QUIETLY and REQUIRED arguments and set LIBNET_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(${CMAKE_ROOT}/Modules/FindPackageHandleStandardArgs.cmake)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(LIBNET DEFAULT_MSG LIBNET_LIBRARY LIBNET_INCLUDE_DIR)

if(LIBNET_FOUND)
	set(LIBNET_LIBRARY ${LIBNET_LIBRARY})
	set(LIBNET_INCLUDE_DIR ${LIBNET_INCLUDE_DIR})
endif(LIBNET_FOUND)
