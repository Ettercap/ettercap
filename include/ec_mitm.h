
/* $Id: ec_mitm.h,v 1.4 2003/11/11 14:59:31 alor Exp $ */

#ifndef EC_MITM_H
#define EC_MITM_H


struct mitm_method {
   char *name;
   void (*start)(char *args);
   void (*stop)(void);
};


/* exported functions */

extern void mitm_add(struct mitm_method *mm);
extern int mitm_set(u_char *name);
extern void mitm_start(void);
extern void mitm_stop(void);
extern void only_mitm(void);

#endif

/* EOF */

// vim:ts=3:expandtab

