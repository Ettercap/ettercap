#ifndef ETTERCAP_GLOBALS_H
#define ETTERCAP_GLOBALS_H

#include <ec_sniff.h>
#include <ec_inet.h>
#include <ec_network.h>
#include <ec_ui.h>
#include <ec_set.h>
#include <ec_stats.h>
#include <ec_profiles.h>
#include <ec_filter.h>
#include <ec_interfaces.h>
#include <config.h>
#include <ec_encryption.h>
#include <ec_utils.h>
#include <pcap.h>
#include <libnet.h>
#include <regex.h>

/* options form etter.conf */
struct ec_conf {
   char *file;
   int ec_uid;
   int ec_gid;
   int arp_storm_delay;
   int arp_poison_smart;
   int arp_poison_warm_up;
   int arp_poison_delay;
   int arp_poison_icmp;
   int arp_poison_reply;
   int arp_poison_request;
   int arp_poison_equal_mac;
   int dhcp_lease_time;
   int port_steal_delay;
   int port_steal_send_delay;
#ifdef WITH_IPV6
   int ndp_poison_warm_up;
   int ndp_poison_delay;
   int ndp_poison_send_delay;
   int ndp_poison_icmp;
   int ndp_poison_equal_mac;
   int icmp6_probe_delay;
#endif
   int connection_timeout;
   int connection_idle;
   int connection_buffer;
   int connect_timeout;
   int sampling_rate;
   int close_on_eof;
   int aggressive_dissectors;
   int skip_forwarded;
   int checksum_check;
   int submit_fingerprint;
   int checksum_warning;
   int sniffing_at_startup;
   int geoip_support_enable;
   int gtkui_prefer_dark_theme;
   int store_profiles;
   struct curses_color colors;
   char *redir_command_on;
   char *redir_command_off;
#ifdef WITH_IPV6
   char *redir6_command_on;
   char *redir6_command_off;
#endif
   char *remote_browser;
   char *utf8_encoding;
   char *geoip_data_file;
   char *geoip_data_file_v6;
};

/* options from getopt */
struct ec_options {
   char write:1;
   char read:1;
   char compress:1;
   char quiet:1;
   char superquiet:1;
   char silent:1;
   char ip6scan:1;
   char unoffensive:1;
   char ssl_mitm:1;
   char load_hosts:1;
   char save_hosts:1;
   char resolve:1;
   char ext_headers:1;
   char mitm:1;
   char only_mitm:1;
   char remote:1;
   char gateway:1;
   char lifaces:1;
   char broadcast:1;
   char reversed;
   char *hostsfile;
   LIST_HEAD(plugin_list_t, plugin_list) plugins;
   char *proto;
   char *netmask;
   char *address;
   char *iface;
   char *iface_bridge;
   char **secondary;
   char *pcapfile_in;
   char *pcapfile_out;
   char *target1;
   char *target2;
   char *script;
   char *ssl_cert;
   char *ssl_pkey;
   FILE *msg_fd;
   int (*format)(const u_char *, size_t, u_char *);
   regex_t *regex;
};

/* program name and version */
struct program_env {
   char *name;
   char *version;
   char *debug_file;
};

/* global pcap structure */
struct pcap_env {
   pcap_if_t     *ifs;
   u_int8         align;         /* alignment needed on sparc 4*n - sizeof(media_hdr) */
   char           promisc;
   char          *filter;        /* pcap filter */
   int            snaplen;
   int            dlt;
   pcap_dumper_t *dump;
   u_int32        dump_size;     /* total dump size */
   u_int32        dump_off;      /* current offset */
};

/* lnet structure */
struct lnet_env {
   libnet_t *lnet_IP4;
   libnet_t *lnet_IP6;
};

/* ip list per target */
struct ip_list {
   struct ip_addr ip;
   LIST_ENTRY(ip_list) next;
};

/* scanned hosts list */
struct hosts_list {
   struct ip_addr ip;
   u_int8 mac[MEDIA_ADDR_LEN];
   char *hostname;
   LIST_ENTRY(hosts_list) next;
};

/* target specifications */
struct target_env {
   char scan_all:1;
   char all_mac:1;            /* these one bit flags are used as wildcards */
   char all_ip:1;
   char all_ip6:1;
   char all_port:1;
   char *proto;
   u_char mac[MEDIA_ADDR_LEN];
   LIST_HEAD(, ip_list) ips;
   LIST_HEAD(, ip_list) ip6;
   u_int8 ports[1<<13];       /* in 8192 byte we have 65535 bits, use one bit per port */
};

/* wifi network structure */
struct wifi_env {
	char wireless;               /* if the send interface is wireless */
	u_char wifi_schema;
      #define WIFI_WEP 0x01
      #define WIFI_WPA 0x02
	char *wifi_key;              /* user specified wifi_key */
	u_char wkey[MAX_WKEY_LEN];   /* encoded wifi key, large enough for all encryption schemas */
	size_t wkey_len;
};

/* the globals container */
struct ec_globals {
   struct ec_conf *conf;
   struct ec_options *options;
   struct gbl_stats *stats;
   struct ui_ops *ui;
   struct program_env *env;
   struct pcap_env *pcap;
   struct lnet_env *lnet;
   struct iface_env *iface;
   struct iface_env *bridge;
   struct sniffing_method *sm;
   struct target_env *t1;
   struct target_env *t2;
   struct wifi_env *wifi;
   LIST_HEAD(, hosts_list) hosts_list;
   TAILQ_HEAD(gbl_ptail, host_profile) profiles_list_head;
   struct filter_list *filters;
};

EC_API_EXTERN struct ec_globals *ec_gbls;

#define EC_GBLS ec_gbls

#define EC_GBL_CONF           (EC_GBLS->conf)
#define EC_GBL_OPTIONS        (EC_GBLS->options)
#define EC_GBL_STATS          (EC_GBLS->stats)
#define EC_GBL_UI             (EC_GBLS->ui)
#define EC_GBL_ENV            (EC_GBLS->env)
#define EC_GBL_PCAP           (EC_GBLS->pcap)
#define EC_GBL_LNET           (EC_GBLS->lnet)
#define EC_GBL_IFACE          (EC_GBLS->iface)
#define EC_GBL_BRIDGE         (EC_GBLS->bridge)
#define EC_GBL_SNIFF          (EC_GBLS->sm)
#define EC_GBL_TARGET1        (EC_GBLS->t1)
#define EC_GBL_TARGET2        (EC_GBLS->t2)
#define EC_GBL_WIFI           (EC_GBLS->wifi)
#define EC_GBL_HOSTLIST       (EC_GBLS->hosts_list)
#define EC_GBL_PROFILES       (EC_GBLS->profiles_list_head)
#define EC_GBL_FILTERS        &(EC_GBLS->filters)

#define EC_GBL_FORMAT         (EC_GBL_OPTIONS->format)

#define EC_GBL_PROGRAM        (EC_GBL_ENV->name)
#define EC_GBL_VERSION        (EC_GBL_ENV->version)
#define EC_GBL_DEBUG_FILE     (EC_GBL_ENV->debug_file)

/* exported functions */

EC_API_EXTERN void ec_globals_alloc(void);
EC_API_EXTERN void ec_globals_free(void);

#endif

/* EOF */

// vim:ts=3:expandtab

