
/* $Id: ec.h,v 1.18 2003/10/22 20:35:56 alor Exp $ */

#ifndef EC_H
#define EC_H

#ifdef HAVE_CONFIG_H
   #include <config.h>
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <stdio.h>
#include <stdlib.h>
#if !defined (__USE_GNU)  /* for memmem(), strsignal(), etc etc... */
   #define __USE_GNU
#endif
#include <string.h>
#if defined (__USE_GNU)
   #undef __USE_GNU
#endif
#include <strings.h>
#include <unistd.h>
#include <time.h>

/* use this file, all the other aren't good */
#include <missing/queue.h>

#include <ec_error.h>
#include <ec_debug.h>
#include <ec_stdint.h>
#include <ec_globals.h>


#define SAFE_CALLOC(x, n, s) do { \
   x = calloc(n, s); \
   ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define SAFE_REALLOC(x, s) do { \
   x = realloc(x, s); \
   ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define __init __attribute__ ((constructor))

#ifndef __set_errno
#define __set_errno(e) (errno = (e))
#endif

#define LOOP for(;;)

#define EXECUTE(x, ...) do{ if(x != NULL) x( __VA_ARGS__ ); }while(0)

/* min and max */

#ifndef MIN
   #define MIN(a, b)    (((a) < (b)) ? (a) : (b))
#endif
#ifndef MAX
   #define MAX(a, b)    (((a) > (b)) ? (a) : (b))
#endif

/* bit operations */

#define BIT_SET(r,b)       ( r[b>>3] |=   1<<(b&7) )
#define BIT_RESET(r,b)     ( r[b>>3] &= ~ 1<<(b&7) )
#define BIT_TEST(r,b)      ( r[b>>3]  &   1<<(b&7) )
#define BIT_NOT(r,b)       ( r[b>>3] ^=   1<<(b&7) )

/* Save and restore relative offsets for pointers into a buffer */
#define SAVE_OFFSET(o,b)     o=(u_int8 *)((int)o-(int)b)
#define RESTORE_OFFSET(o,b)  o=(u_int8 *)((int)o+(int)b)   

/* ANSI colors */

#define EC_COLOR_END    "\033[0m"
#define EC_COLOR_BOLD   "\033[1m"

#define EC_COLOR_RED    "\033[31m"EC_COLOR_BOLD
#define EC_COLOR_YELLOW "\033[33m"EC_COLOR_BOLD
#define EC_COLOR_GREEN  "\033[32m"EC_COLOR_BOLD
#define EC_COLOR_BLUE   "\033[34m"EC_COLOR_BOLD
#define EC_COLOR_CYAN   "\033[36m"EC_COLOR_BOLD

/* magic numbers */

#define EC_MAGIC_8   0xec
#define EC_MAGIC_16  0xe77e
#define EC_MAGIC_32  0xe77ee77e

/* exported by ec_main */
extern void clean_exit(int errcode);


#endif   /*  EC_H */

/* EOF */

// vim:ts=3:expandtab

