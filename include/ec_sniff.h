
/* $Id: ec_sniff.h,v 1.10 2004/03/31 13:03:08 alor Exp $ */

#ifndef EC_SNIFF_H
#define EC_SNIFF_H

#include <ec_packet.h>

struct sniffing_method {
   char type;              /* the type of the sniffing method */
      #define SM_UNIFIED      0
      #define SM_BRIDGED      1
   char active;            /* true if the sniff was started */
   void (*start)(void);
   void (*cleanup)(void);
   void (*check_forwarded)(struct packet_object *po);
   void (*set_forwardable)(struct packet_object *po);
   void (*forward)(struct packet_object *po);
   void (*interesting)(struct packet_object *po);  /* this function set the PO_IGNORE flag */
};

/* exported functions */

/* forwarder (the struct is in ec_globals.h) */
struct target_env;

extern void set_sniffing_method(struct sniffing_method *sm);

extern void set_unified_sniff(void);
extern void set_bridge_sniff(void);

extern int compile_display_filter(void);
extern int compile_target(char *string, struct target_env *target);

extern void reset_display_filter(struct target_env *t);

extern void del_ip_list(struct ip_addr *ip, struct target_env *t);
extern int cmp_ip_list(struct ip_addr *ip, struct target_env *t);
extern void add_ip_list(struct ip_addr *ip, struct target_env *t);
extern void free_ip_list(struct target_env *t);

#endif

/* EOF */

// vim:ts=3:expandtab

