
/* $Id: ec_conf.h,v 1.4 2004/03/26 17:22:17 alor Exp $ */

#ifndef EC_CONF_H
#define EC_CONF_H


struct conf_entry {
   char *name;
   void *value;
};

struct conf_section {
   char *title;
   struct conf_entry *entries;
};


/* exported functions */

extern void load_conf(void);
extern void conf_dissectors(void);

#endif

/* EOF */

// vim:ts=3:expandtab

