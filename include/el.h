#ifndef ETTERLOG_H
#define ETTERLOG_H

#include <ec.h>
#include <ec_log.h>
#include <el_version.h>
#include <ec_version.h>

struct el_options {
   char concat:1;
   char analyze:1;
   char no_headers:1;
   char connections:1;
   char decode:1;
   char showmac:1;
   char showclient:1;
   char only_source:1;
   char only_dest:1;
   char only_local:1;
   char only_remote:1;
   char passwords:1;
   char color:1;
   char xml:1;
   char reverse:1;
   char regex:1;
};

struct el_globals {
   struct log_global_header hdr;
   int (*format)(const u_char *, size_t, u_char *);
   char *user;
   char *logfile;
   gzFile fd;
   regex_t *regex;
   struct target_env *t;
   struct ip_addr client;
   struct el_options *options;
};

/* in el_main.c */
extern struct el_globals *el_gbls;

#define EL_GBL el_gbls


#define EL_GBL_LOGFILE EL_GBL->logfile
#define EL_GBL_LOG_FD  EL_GBL->fd
#define EL_GBL_OPTIONS EL_GBL->options
#define EL_GBL_TARGET (EL_GBL->t)

#define COL_RED      31
#define COL_GREEN    32
#define COL_YELLOW   33
#define COL_BLUE     34
#define COL_MAGENTA  35
#define COL_CYAN     36

EC_API_EXTERN void el_globals_alloc(void);
EC_API_EXTERN void el_globals_free(void);
EC_API_EXTERN void el_exit(int code);

#endif   /*  EL_H */

/* EOF */

// vim:ts=3:expandtab

