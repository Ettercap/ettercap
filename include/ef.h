
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


#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define __init __attribute__ ((constructor))

#define LOOP for(;;)


struct globals {
   char test:1;
   char *source_file;
   char *output_file;
};

/* in el_main.c */
extern struct globals gbls;

#define GBL_OPTIONS gbls

#define GBL_PROGRAM "etterfilter"


#define BIT_SET(r,b)       ( r[b>>3] |=   1<<(b&7) )
#define BIT_RESET(r,b)     ( r[b>>3] &= ~ 1<<(b&7) )
#define BIT_TEST(r,b)      ( r[b>>3]  &   1<<(b&7) )
#define BIT_NOT(r,b)       ( r[b>>3] ^=   1<<(b&7) )


/* ANSI colors */

#define EC_COLOR_END    "\033[0m"
#define EC_COLOR_BOLD   "\033[1m"

#define EC_COLOR_RED    "\033[31m"EC_COLOR_BOLD
#define EC_COLOR_YELLOW "\033[33m"EC_COLOR_BOLD
#define EC_COLOR_GREEN  "\033[32m"EC_COLOR_BOLD
#define EC_COLOR_BLUE   "\033[34m"EC_COLOR_BOLD
#define EC_COLOR_CYAN   "\033[36m"EC_COLOR_BOLD


#endif   /*  EL_H */

/* EOF */

// vim:ts=3:expandtab

