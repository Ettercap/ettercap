
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

	typedef int8_t    int8;
	typedef int16_t   int16;
	typedef int32_t   int32;
	typedef int64_t   int64;

	typedef uint8_t   u_int8;
	typedef uint16_t  u_int16;
	typedef uint32_t  u_int32;
	typedef uint64_t  u_int64;

#endif

/* EOF */

// vim:ts=3:expandtab
