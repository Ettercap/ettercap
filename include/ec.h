
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
#ifdef HAVE_SYS_QUEUE
   #include <sys/queue.h>
#else
   #include <missing/queue.h>
#endif

#include <ec_error.h>
#include <ec_debug.h>
#include <ec_stdint.h>
#include <ec_globals.h>


#ifndef HAVE_STRLCAT
   #include <missing/strlcat.h>
#endif
#ifndef HAVE_STRLCPY 
   #include <missing/strlcpy.h>
#endif
#ifndef HAVE_STRSEP 
   #include <missing/strsep.h>
#endif

#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define __init __attribute__ ((constructor))

#ifndef __set_errno
#define __set_errno(e) (errno = (e))
#endif

#define LOOP for(;;)

#define EXECUTE(x, ...) do{ if(x != NULL) x( __VA_ARGS__ ); }while(0)

/* this is a default uid to drop privs to */
#define DROP_TO_UID 65534


#define BIT_SET(r,b)       ( r[b>>3] |=   1<<(b&7) )
#define BIT_RESET(r,b)     ( r[b>>3] &= ~ 1<<(b&7) )
#define BIT_TEST(r,b)      ( r[b>>3]  &   1<<(b&7) )
#define BIT_NOT(r,b)       ( r[b>>3] ^=   1<<(b&7) )

/* exported by ec_main */
extern void clean_exit(int errcode);


#endif   /*  EC_H */

/* EOF */

// vim:ts=3:expandtab

