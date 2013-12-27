#ifndef ETTERCAP_PASSIVE_H_DF4881C6F3E04D63A709E2095265E5D1
#define ETTERCAP_PASSIVE_H_DF4881C6F3E04D63A709E2095265E5D1

EC_API_EXTERN int is_open_port(u_int8 proto, u_int16 port, u_int8 flags);
EC_API_EXTERN void print_host(struct host_profile *h); 
EC_API_EXTERN void print_host_xml(struct host_profile *h);

#endif

/* EOF */

// vim:ts=3:expandtab

