#ifndef ETTERFILTER_H
#define ETTERFILTER_H

#include <config.h>

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

#ifndef HAVE_STRSEP
   #include <missing/strsep.h>
#endif

#ifdef OS_WINDOWS
   #include <windows.h>
#endif

#include <ec_queue.h>
#include <ec_stdint.h>
#include <ec_error.h>
#include <ec_strings.h>

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

#define LOOP for(;;)

/* file operations */ 
#ifndef OS_WINDOWS
   #define O_BINARY  0
#endif

struct ef_globals {
   char *source_file;
   char *output_file;
   u_int32 lineno;
   u_int8 debug;
   u_int8 suppress_warnings;
};

/* in el_main.c */
extern struct ef_globals *ef_gbls;

#define EF_GBL         ef_gbls
#define EF_GBL_OPTIONS EF_GBL

EC_API_EXTERN void ef_globals_alloc(void);
EC_API_EXTERN void ef_globals_free(void);

#endif   /*  EL_H */

/* EOF */

// vim:ts=3:expandtab

