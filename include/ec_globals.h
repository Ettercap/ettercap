
#ifndef EC_GLOBALS_H
#define EC_GLOBALS_H

#include <ec_sniff.h>
#include <ec_inet.h>
#include <ec_ui.h>
#include <ec_stats.h>
#include <pcap.h>

/* options from getopt */
struct ec_options {
   char write:1;
   char read:1;
   char compress:1;
   char quiet:1;
   char silent:1;
   char load_hosts:1;
   char save_hosts:1;
   char resolve:1;
   char reversed;
   int scan_delay;
   char *hostsfile;
   char *plugin;
   char *proto;
   char *netmask;
   char *iface;
   char *iface_bridge;
   char *dumpfile;
   char *target1;
   char *target2;
};

/* program name and version */
struct program_env {
   char *name;
   char *version;
   char *debug_file;
};

/* pcap structures */
struct pcap_env {
   pcap_t            *pcap;      
   pcap_t            *pcap_bridge;
   pcap_dumper_t     *dump;
   char              promisc:1;
   char              *filter;       /* pcap filter */
   u_int16           snaplen;
   int               dlt;
   u_int32           dump_size;     /* total dump size */
   u_int32           dump_off;      /* current offset */
};

/* lnet structures */
struct lnet_env {
   void *lnet_L3;       /* this is a libnet_t pointer */
   void *lnet;          /* this is a libnet_t pointer */ 
   void *lnet_bridge;   /* this is a libnet_t pointer */
};

/* per interface informations */
struct iface_env {
   struct ip_addr ip;
   struct ip_addr network;
   struct ip_addr netmask;
   u_char mac[ETH_ADDR_LEN];
};

/* ip list per target */
struct ip_list {
   struct ip_addr ip;
   SLIST_ENTRY(ip_list) next;
};

/* target specifications */
struct target_env {
   char all_mac:1;            /* these one bit flags are used as wildcards */
   char all_ip:1;
   char all_port:1;
   u_char mac[ETH_ADDR_LEN];
   SLIST_HEAD (, ip_list) ips;
   u_int8 ports[1<<13];       /* in 8192 byte we have 65535 bits, use one bit per port */
};

/* scanned hosts list */
struct hosts_list {
   struct ip_addr ip;
   u_char mac[ETH_ADDR_LEN];
   char *hostname;
   LIST_ENTRY(hosts_list) next;
};

/* the globals container */
struct globals {
   struct gbl_stats *stats;
   struct ec_options *options;
   struct ui_ops *ui;
   struct program_env *env;
   struct pcap_env *pcap;
   struct lnet_env *lnet;
   struct iface_env *iface;
   struct iface_env *bridge;
   struct sniffing_method *sm;
   struct target_env *t1;
   struct target_env *t2;
   LIST_HEAD(, hosts_list) hosts_list_head;
};

extern struct globals *gbls;

#define GBLS gbls

#define GBL_STATS          (GBLS->stats)
#define GBL_OPTIONS        (GBLS->options)
#define GBL_UI             (GBLS->ui)
#define GBL_ENV            (GBLS->env)
#define GBL_PCAP           (GBLS->pcap)
#define GBL_LNET           (GBLS->lnet)
#define GBL_IFACE          (GBLS->iface)
#define GBL_BRIDGE         (GBLS->bridge)
#define GBL_SNIFF          (GBLS->sm)
#define GBL_TARGET1        (GBLS->t1)
#define GBL_TARGET2        (GBLS->t2)
#define GBL_HOSTLIST       (GBLS->hosts_list_head)

#define GBL_PROGRAM        (GBL_ENV->name)
#define GBL_VERSION        (GBL_ENV->version)
#define GBL_DEBUG_FILE     (GBL_ENV->debug_file)


/* exported functions */

extern void globals_alloc(void);
extern void globals_free(void);

#endif

/* EOF */

// vim:ts=3:expandtab

