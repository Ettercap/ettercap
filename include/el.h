
/* $Id: el.h,v 1.10 2003/09/27 17:22:02 alor Exp $ */

#ifndef EL_H
#define EL_H

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

#define SAFE_CALLOC(x, n, s) do { \
   x = calloc(n, s); \
   ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define __init __attribute__ ((constructor))

#define LOOP for(;;)

struct ip_list {
   struct ip_addr ip;
   SLIST_ENTRY(ip_list) next;
};

struct target_env {
   char all_mac:1;            /* these one bit flags are used as wildcards */
   char all_ip:1;
   char all_port:1;
   char *proto;
   u_char mac[ETH_ADDR_LEN];
   SLIST_HEAD (, ip_list) ips;
   u_int8 ports[1<<13];       /* in 8192 byte we have 65535 bits, use one bit per port */
};

struct globals {
   struct log_global_header hdr;
   char analyze:1;
   char no_headers:1;
   char connections:1;
   char showmac:1;
   char reverse:1;
   char only_source:1;
   char only_dest:1;
   char only_local:1;
   char only_remote:1;
   char passwords:1;
   char color:1;
   char xml:1;
   int (*format)(const u_char *, size_t, u_char *);
   char *user;
   char *logfile;
   gzFile fd;
   regex_t *regex;
   struct target_env *t;
};

/* in el_main.c */
extern struct globals gbls;

#define GBL gbls

#define GBL_PROGRAM "etterlog"
#define GBL_LOGFILE GBL.logfile
#define GBL_LOG_FD  GBL.fd
#define GBL_TARGET (GBL.t)



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

#define COL_RED      31
#define COL_GREEN    32
#define COL_YELLOW   33
#define COL_BLUE     34
#define COL_MAGENTA  35
#define COL_CYAN     36


#endif   /*  EL_H */

/* EOF */

// vim:ts=3:expandtab

