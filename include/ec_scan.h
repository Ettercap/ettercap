
#ifndef EC_SCAN_H
#define EC_SCAN_H

extern void build_hosts_list(void);
extern void del_hosts_list(void);
extern void add_host(struct ip_addr *ip, u_int8 mac[ETH_ADDR_LEN], char *name);


#endif

/* EOF */

// vim:ts=3:expandtab

