
#ifndef EF_H
#define EF_H

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
#include <missing/queue.h>

#ifndef HAVE_STRSEP
   #include <missing/strsep.h>
#endif

#include <ec_stdint.h>
#include <ec_error.h>
#include <ec_log.h>
#include <ec_profiles.h>

#include <zlib.h>
#include <regex.h>

#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define __init __attribute__ ((constructor))

#define LOOP for(;;)


struct globals {
};

/* in el_main.c */
extern struct globals gbls;

#define GBL gbls

#define GBL_PROGRAM "etterfilter"


#define BIT_SET(r,b)       ( r[b>>3] |=   1<<(b&7) )
#define BIT_RESET(r,b)     ( r[b>>3] &= ~ 1<<(b&7) )
#define BIT_TEST(r,b)      ( r[b>>3]  &   1<<(b&7) )
#define BIT_NOT(r,b)       ( r[b>>3] ^=   1<<(b&7) )


/* ANSI colors */

#define END_COLOR    "\033[0m"
#define BOLD_COLOR   "\033[1m"

#define COLOR_RED    "\033[31m"BOLD_COLOR
#define COLOR_YELLOW "\033[33m"BOLD_COLOR
#define COLOR_GREEN  "\033[32m"BOLD_COLOR
#define COLOR_BLU    "\033[34m"BOLD_COLOR
#define COLOR_CYAN   "\033[36m"BOLD_COLOR


#endif   /*  EL_H */

/* EOF */

// vim:ts=3:expandtab

