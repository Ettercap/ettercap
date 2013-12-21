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

if( WIN32 )
	FIND_PATH( LIBIDN_INCLUDE_DIR stringprep.h $ENV{INCLUDE} )
	FIND_LIBRARY( LIBIDN_LIBRARIES libidn $ENV{LIB} )
else( )
	FIND_PATH( LIBIDN_INCLUDE_DIR stringprep.h )
	FIND_LIBRARY( LIBIDN_LIBRARIES idn )
endif( )

if( LIBIDN_LIBRARIES AND LIBIDN_INCLUDE_DIR )
	message( STATUS "Found libidn: ${LIBIDN_LIBRARIES}" )
	set( LIBIDN_FOUND true )
else( LIBIDN_LIBRARIES AND LIBIDN_INCLUDE_DIR )
	message( STATUS "Could NOT find libidn" )
endif( LIBIDN_LIBRARIES AND LIBIDN_INCLUDE_DIR )