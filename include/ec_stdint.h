
/* $Id: ec_stdint.h,v 1.5 2003/12/27 16:08:47 alor Exp $ */

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

   #ifdef OS_OPENBSD
      #define INT8_MAX     CHAR_MAX
      #define UINT8_MAX    UCHAR_MAX
      #define INT16_MAX    SHRT_MAX
      #define UINT16_MAX   USHRT_MAX
      #define INT32_MAX    INT_MAX
      #define UINT32_MAX   UINT_MAX
   #endif
   
#endif
   
#endif

/* EOF */

// vim:ts=3:expandtab
