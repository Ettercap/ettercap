
/* $Id: ec_stdint.h,v 1.4 2003/11/16 21:11:53 alor Exp $ */

#ifndef EC_STDINT_H
#define EC_STDINT_H

#include <limits.h>

#if defined HAVE_STDINT_H && !defined OS_SOLARIS

	#include <stdint.h>

#elif !defined OS_SOLARIS
	
	#include <sys/types.h>

#elif defined OS_SOLARIS

	#include <sys/inttypes.h>

#endif

#ifndef TYPES_DEFINED
#define TYPES_DEFINED
	typedef int8_t    int8;
	typedef int16_t   int16;
	typedef int32_t   int32;
	typedef int64_t   int64;

	typedef uint8_t   u_int8;
	typedef uint16_t  u_int16;
	typedef uint32_t  u_int32;
	typedef uint64_t  u_int64;
#endif
   
#endif

/* EOF */

// vim:ts=3:expandtab
