
#ifndef EC_PASSIVE_H
#define EC_PASSIVE_H

extern int is_open_port(u_int8 proto, u_int16 port, u_int8 flags);
extern void print_host(struct host_profile *h); 
extern void print_host_xml(struct host_profile *h);

#endif

/* EOF */

// vim:ts=3:expandtab

