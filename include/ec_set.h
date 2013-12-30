#ifndef ETTERCAP_SET_H
#define ETTERCAP_SET_H

EC_API_EXTERN void set_mitm(char *mitm);
EC_API_EXTERN void set_onlymitm(void);
EC_API_EXTERN void set_broadcast(void);
EC_API_EXTERN void set_iface_bridge(char *iface);
EC_API_EXTERN void set_promisc(void);
EC_API_EXTERN void set_reversed(void);
EC_API_EXTERN void set_proto(char *arg);
EC_API_EXTERN void set_plugin(char *name);
EC_API_EXTERN void set_iface(char *iface);
EC_API_EXTERN void set_lifaces(void);
EC_API_EXTERN void set_secondary(char *iface);
EC_API_EXTERN void set_netmask(char *netmask);
EC_API_EXTERN void set_address(char *address);
EC_API_EXTERN void set_read_pcap(char *pcap_file);
EC_API_EXTERN void set_write_pcap(char *pcap_file);
EC_API_EXTERN void set_pcap_filter(char *filter);
EC_API_EXTERN void set_filter(char *end, const char *filter);
EC_API_EXTERN void set_loglevel_packet(char *arg);
EC_API_EXTERN void set_loglevel_info(char *arg);
EC_API_EXTERN void set_loglevel_true(char *arg);
EC_API_EXTERN void set_compress(void);
EC_API_EXTERN void opt_set_regex(char *regex);
EC_API_EXTERN void set_quiet(void);
EC_API_EXTERN void set_superquiet(void);
EC_API_EXTERN void set_script(char *script);
EC_API_EXTERN void set_silent(void);
#ifdef WITH_IPV6
EC_API_EXTERN void set_ip6scan(void);
#endif
EC_API_EXTERN void set_unoffensive(void);
EC_API_EXTERN void disable_sslmitm(void);
EC_API_EXTERN void set_resolve(void);
EC_API_EXTERN void set_load_hosts(char *file);
EC_API_EXTERN void set_save_hosts(char *file);
EC_API_EXTERN void opt_set_format(char *format);
EC_API_EXTERN void set_ext_headers(void);
EC_API_EXTERN void set_wifi_key(char *key);
EC_API_EXTERN void set_conf_file(char *file);
EC_API_EXTERN void set_ssl_cert(char *cert);
EC_API_EXTERN void set_ssl_key(char *key);
#ifdef HAVE_EC_LUA
EC_API_EXTERN void set_lua_args(char *args);
EC_API_EXTERN void set_lua_script(char *script);
#endif
EC_API_EXTERN void set_target_target1(char *target1);
EC_API_EXTERN void set_target_target2(char *target2);
#endif

/* EOF */

// vim:ts=3:expandtab

