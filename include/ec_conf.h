#ifndef ETTERCAP_CONF_H_79914B1B703346DA84BD5E0ACAF0DECA
#define ETTERCAP_CONF_H_79914B1B703346DA84BD5E0ACAF0DECA

struct conf_entry {
   char *name;
   void *value;
};

struct conf_section {
   char *title;
   struct conf_entry *entries;
};


/* exported functions */

EC_API_EXTERN void load_conf(void);
EC_API_EXTERN void conf_dissectors(void);

#endif

/* EOF */

// vim:ts=3:expandtab

