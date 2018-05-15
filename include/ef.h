#ifndef ETTERFILTER_H
#define ETTERFILTER_H

#include <ec.h>
#include <ef_version.h>
#include <ec_version.h>

struct ef_globals {
   char *source_file;
   char *output_file;
   u_int32 lineno;
   u_int8 debug;
   u_int8 suppress_warnings;
};

/* in el_main.c */
extern struct ef_globals *ef_gbls;

#define EF_GBL_OPTIONS  ef_gbls
#define EF_GBL          ef_gbls

EC_API_EXTERN void ef_globals_alloc(void);
EC_API_EXTERN void ef_globals_free(void);
EC_API_EXTERN void ef_exit(int code);

#endif   /*  EL_H */

/* EOF */

// vim:ts=3:expandtab

