
/* $Id: ec_mitm.h,v 1.6 2004/01/21 21:17:16 alor Exp $ */

#ifndef EC_MITM_H
#define EC_MITM_H


struct mitm_method {
   char *name;
   int (*start)(char *args);
   void (*stop)(void);
};


/* exported functions */

extern void mitm_add(struct mitm_method *mm);
extern int mitm_set(u_char *name);
extern int mitm_start(void);
extern void mitm_stop(void);
extern void only_mitm(void);

#endif

/* EOF */

// vim:ts=3:expandtab

