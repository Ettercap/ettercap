
#ifndef EC_GLOBALS_H
#define EC_GLOBALS_H

#include <ec_sniff.h>
#include <ec_inet.h>
#include <ec_ui.h>

struct ec_options {
   char dump:1;
   char read:1;
   char reversed;
   char *plugin;
   char *proto;
   char *iface;
   char *iface_bridge;
   char *dumpfile;
   char *target1;
   char *target2;
};

struct program_env {
   char *name;
   char *version;
   char *debug_file;
};

struct pcap_env {
   void *pcap;          /* this is a pcap_t */
   void *pcap_bridge;   /* this is a pcap_t */
   void *dump;          /* this is a pcap_dumper_t */
   char promisc:1;
   char *filter;        /* pcap filter */
   u_int16 snaplen;
   int dlt;
};

struct lnet_env {
   void *lnet_L3;       /* this is a libnet_t */
   void *lnet;          /* this is a libnet_t */
   void *lnet_bridge;   /* this is a libnet_t */
};

struct iface_env {
   struct ip_addr ip;
   struct ip_addr network;
   struct ip_addr netmask;
   u_char mac[ETH_ADDR_LEN];
};


struct ip_list {
   struct ip_addr ip;
   SLIST_ENTRY(ip_list) next;
};

struct target_env {
   char all_mac:1;            /* these one bit flags are used as wildcards */
   char all_ip:1;
   char all_port:1;
   u_char mac[ETH_ADDR_LEN];
   SLIST_HEAD (, ip_list) ips;
   u_int8 ports[1<<13];       /* in 8192 byte we have 65535 bits, use one bit per port */
};

struct globals {
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
};

extern struct globals *gbls;

#define GBLS gbls

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

#define GBL_PROGRAM        (GBL_ENV->name)
#define GBL_VERSION        (GBL_ENV->version)
#define GBL_DEBUG_FILE     (GBL_ENV->debug_file)


/* exported functions */

extern void globals_alloc(void);

#endif

/* EOF */

// vim:ts=3:expandtab

