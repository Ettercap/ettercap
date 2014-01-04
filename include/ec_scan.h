#ifndef ETTERCAP_SCAN_H_3E82F02ED569476CAE3D05C37B2C8404
#define ETTERCAP_SCAN_H_3E82F02ED569476CAE3D05C37B2C8404

EC_API_EXTERN void build_hosts_list(void);
EC_API_EXTERN void del_hosts_list(void);
EC_API_EXTERN void add_host(struct ip_addr *ip, u_int8 mac[MEDIA_ADDR_LEN], char *name);

EC_API_EXTERN int scan_load_hosts(char *filename);
EC_API_EXTERN int scan_save_hosts(char *filename);

#endif

/* EOF */

// vim:ts=3:expandtab

