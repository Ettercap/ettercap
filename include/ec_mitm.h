
/* $Id: ec_mitm.h,v 1.8 2004/07/24 10:43:21 alor Exp $ */

#ifndef EC_MITM_H
#define EC_MITM_H


struct mitm_method {
   char *name;
   int (*start)(char *args);
   void (*stop)(void);
};


/* exported functions */

EC_API_EXTERN void mitm_add(struct mitm_method *mm);
EC_API_EXTERN int mitm_set(char *name);
EC_API_EXTERN int mitm_start(void);
EC_API_EXTERN void mitm_stop(void);
EC_API_EXTERN void only_mitm(void);
EC_API_EXTERN int is_mitm_active(char *name);

#endif

/* EOF */

// vim:ts=3:expandtab

