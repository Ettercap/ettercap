
/* $Id: ec_scan.h,v 1.5 2003/12/14 20:57:27 alor Exp $ */

#ifndef EC_SCAN_H
#define EC_SCAN_H

extern void build_hosts_list(void);
extern void del_hosts_list(void);
extern void add_host(struct ip_addr *ip, u_int8 mac[MEDIA_ADDR_LEN], char *name);

extern int scan_load_hosts(char *filename);

#endif

/* EOF */

// vim:ts=3:expandtab

