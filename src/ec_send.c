/*
    ettercap -- send the the wire functions

    Copyright (C) ALoR & NaGA

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id: ec_send.c,v 1.23 2003/10/28 21:10:55 alor Exp $
*/

#include <ec.h>
#include <ec_packet.h>
#include <ec_send.h>

#include <pthread.h>
#include <pcap.h>
#include <libnet.h>

/* globals */

u_int8 MEDIA_BROADCAST[MEDIA_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
u_int8 ARP_BROADCAST[MEDIA_ADDR_LEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static SLIST_HEAD (, build_entry) builders_table;

struct build_entry {
   u_int8 dlt;
   FUNC_BUILDER_PTR(builder);
   SLIST_ENTRY (build_entry) next;
};

/* protos */

void send_init(void);
static void send_close(void);
int send_to_L3(struct packet_object *po);
int send_to_L2(struct packet_object *po);
int send_to_bridge(struct packet_object *po);

static void hack_pcap_lnet(pcap_t *p, libnet_t *l);

void add_builder(u_int8 dlt, FUNC_BUILDER_PTR(builder));
libnet_ptag_t ec_build_link_layer(u_int8 dlt, u_int8 *dst, u_int16 proto);

int send_arp(u_char type, struct ip_addr *sip, u_int8 *smac, struct ip_addr *tip, u_int8 *tmac);
int send_icmp_echo(u_char type, struct ip_addr *sip, u_int8 *smac, struct ip_addr *tip, u_int8 *tmac);

static pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
#define SEND_LOCK     do{ pthread_mutex_lock(&send_mutex); } while(0)
#define SEND_UNLOCK   do{ pthread_mutex_unlock(&send_mutex); } while(0)

/*******************************************/

/*
 * set up the lnet struct to have a socket to send packets
 */

void send_init(void)
{
   libnet_t *l;
   libnet_t *l3;
   libnet_t *lb;
   char lnet_errbuf[LIBNET_ERRBUF_SIZE];
 
   /* check when to not initialize libnet */
   if (GBL_OPTIONS->read || GBL_OPTIONS->unoffensive) {
      DEBUG_MSG("send_init: skipping... (reading offline of unoffensive)");
      GBL_OPTIONS->unoffensive = 1;
      return;
   }
   
   /* don't send packet on loopback */
   if (!strcasecmp(GBL_OPTIONS->iface, "lo")) {
      DEBUG_MSG("send_init: skipping... (using loopback)");
      GBL_OPTIONS->unoffensive = 1;
      return;
   }

   /* in wireless monitor mode we cannot send packets */
   if (GBL_PCAP->dlt == DLT_IEEE802_11) {
      DEBUG_MSG("send_init: skipping... (using wireless)");
      GBL_OPTIONS->unoffensive = 1;
      return;
   }
   
   DEBUG_MSG("send_init %s", GBL_OPTIONS->iface);
   
   /* open the socket at layer 3 */
   l3 = libnet_init(LIBNET_RAW4_ADV, GBL_OPTIONS->iface, lnet_errbuf);               
   ON_ERROR(l3, NULL, "libnet_init(LIBNET_RAW4_ADV) failed: %s", lnet_errbuf);
   
   /* open the socket at layer 2 ( GBL_OPTIONS->iface doesn't matter ) */
   l = libnet_init(LIBNET_LINK_ADV, GBL_OPTIONS->iface, lnet_errbuf);               
   ON_ERROR(l, NULL, "libnet_init(LIBNET_LINK_ADV) failed: %s", lnet_errbuf);
   
   if (GBL_SNIFF->type == SM_BRIDGED) {
      /* open the socket on the other iface for bridging */
      lb = libnet_init(LIBNET_LINK_ADV, GBL_OPTIONS->iface_bridge, lnet_errbuf);               
      ON_ERROR(lb, NULL, "libnet_init() failed: %s", lnet_errbuf);
      GBL_LNET->lnet_bridge = lb;
      /* use the same socket for lnet and pcap */
      hack_pcap_lnet(GBL_PCAP->pcap_bridge, GBL_LNET->lnet_bridge);
   }
   
   GBL_LNET->lnet_L3 = l3;               
   GBL_LNET->lnet = l;               
      
   /* use the same socket for lnet and pcap */
   hack_pcap_lnet(GBL_PCAP->pcap, GBL_LNET->lnet);

   atexit(send_close);
}


static void send_close(void)
{
   libnet_destroy(GBL_LNET->lnet);
   libnet_destroy(GBL_LNET->lnet_L3);

   if (GBL_SNIFF->type == SM_BRIDGED) 
      libnet_destroy(GBL_LNET->lnet_bridge);
   
   DEBUG_MSG("ATEXIT: send_closed");
}

/*
 * send the packet at layer 3
 * the eth header will be handled by the kernel
 */

int send_to_L3(struct packet_object *po)
{
   /* XXX - ???
    * use one ptag per thread.
    * this should be enough to assure thread safety
    */
   libnet_ptag_t t = (libnet_ptag_t)pthread_self();
   int c;

   /* if not lnet warn the developer ;) */
   BUG_IF(GBL_LNET->lnet == 0);
   
   SEND_LOCK;
   
   t = libnet_build_data( po->fwd_packet, po->fwd_len, GBL_LNET->lnet_L3, 0);
   ON_ERROR(t, -1, "libnet_build_data: %s", libnet_geterror(GBL_LNET->lnet_L3));
   
   c = libnet_write(GBL_LNET->lnet_L3);
   ON_ERROR(c, -1, "libnet_write %d (%d): %s", po->fwd_len, c, libnet_geterror(GBL_LNET->lnet_L3));
   
   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet_L3);
   
   SEND_UNLOCK;
   
   return c;
}

/*
 * send the packet at layer 2
 * this can be used to send ARP messages
 */

int send_to_L2(struct packet_object *po)
{
   /* XXX - ???
    * use one ptag per thread.
    * this should be enough to assure thread safety
    */
   libnet_ptag_t t = (libnet_ptag_t)pthread_self();
   int c;
   
   /* if not lnet warn the developer ;) */
   BUG_IF(GBL_LNET->lnet == 0);
   
   SEND_LOCK;
   
   t = libnet_build_data( po->packet, po->len, GBL_LNET->lnet, 0);
   ON_ERROR(t, -1, "libnet_build_data: %s", libnet_geterror(GBL_LNET->lnet));
   
   c = libnet_write(GBL_LNET->lnet);
   ON_ERROR(c, -1, "libnet_write %d (%d): %s", po->len, c, libnet_geterror(GBL_LNET->lnet));
   
   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet);
   
   SEND_UNLOCK;
   
   return c;
}

/*
 * send the packet to the bridge
 */

int send_to_bridge(struct packet_object *po)
{
   /* XXX - ???
    * use one ptag per thread.
    * this should be enough to assure thread safety
    */
   libnet_ptag_t t = (libnet_ptag_t)pthread_self();
   int c;
  
   /* if not lnet warn the developer ;) */
   BUG_IF(GBL_LNET->lnet == 0);
   
   SEND_LOCK;

   t = libnet_build_data( po->packet, po->len, GBL_LNET->lnet_bridge, 0);
   ON_ERROR(t, -1, "libnet_build_data: %s", libnet_geterror(GBL_LNET->lnet_bridge));
   
   c = libnet_write(GBL_LNET->lnet_bridge);
   ON_ERROR(c, -1, "libnet_write %d (%d): %s", po->len, c, libnet_geterror(GBL_LNET->lnet_bridge));
   
   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet_bridge);
   
   SEND_UNLOCK;
   
   return c;
}

/*
 * we MUST not sniff packets sent by us at link layer.
 * expecially usefull in bridged sniffing.
 *
 * so we have to find a solution...
 */

static void hack_pcap_lnet(pcap_t *p, libnet_t *l)
{
#ifdef OS_LINUX   
   /*
    * a dirty hack to use the same socket for pcap and libnet.
    * both the structures contains a "int fd" field representing the socket.
    * we can close the fd opened by libnet and use the one already in use by pcap.
   */
   
   DEBUG_MSG("hack_pcap_lnet (before) pcap %d | lnet %d", pcap_fileno(p), l->fd);
   /* close the lnet socket */
   close(libnet_getfd(l));
   /* use the socket opened by pcap */
   l->fd = pcap_fileno(p);
   
   DEBUG_MSG("hack_pcap_lnet  (after) pcap %d | lnet %d", pcap_fileno(p), l->fd);
#endif

#ifdef OS_BSD
   /*
    * under BSD we cannot hack the fd as in linux... 
    * pcap opens the /dev/bpf in O_RDONLY and lnet needs O_RDWR
    * 
    * so (if supported: only FreeBSD) we can set the BIOCSSEESENT to 1 to 
    * see only outgoing packets
    * but this is unconfortable, because we will not able to sniff ourself.
    */
   // int val = 0;
   // ioctl(pcap_fileno(p), BIOCSSEESENT, &val);
   DEBUG_MSG("hack_pcap_lnet: not applicable on this OS");
   return;
#endif
   
}


/*
 * helper function to send out an ARP packet
 */
int send_arp(u_char type, struct ip_addr *sip, u_int8 *smac, struct ip_addr *tip, u_int8 *tmac)
{
   libnet_ptag_t t = (libnet_ptag_t)pthread_self();
   u_char *packet;
   u_long packet_s;
   int c;
 
   /* if not lnet warn the developer ;) */
   BUG_IF(GBL_LNET->lnet == 0);
   
   SEND_LOCK;

   /* ARP uses 00:00:00:00:00:00 broadcast */
   if (type == ARPOP_REQUEST && tmac == MEDIA_BROADCAST)
      tmac = ARP_BROADCAST;
   
   /* create the ARP header */
   t = libnet_build_arp(
           ARPHRD_ETHER,            /* hardware addr */
           ETHERTYPE_IP,            /* protocol addr */
           MEDIA_ADDR_LEN,          /* hardware addr size */
           IP_ADDR_LEN,             /* protocol addr size */
           type,                    /* operation type */
           smac,                    /* sender hardware addr */
           (u_char *)&(sip->addr),  /* sender protocol addr */
           tmac,                    /* target hardware addr */
           (u_char *)&(tip->addr),  /* target protocol addr */
           NULL,                    /* payload */
           0,                       /* payload size */
           GBL_LNET->lnet,          /* libnet handle */
           0);                      /* libnet id */
   ON_ERROR(t, -1, "libnet_build_arp: %s", libnet_geterror(GBL_LNET->lnet));
   
   /* MEDIA uses ff:ff:ff:ff:ff:ff broadcast */
   if (type == ARPOP_REQUEST && tmac == ARP_BROADCAST)
      tmac = MEDIA_BROADCAST;
   
   /* add the media header */
   t = ec_build_link_layer(GBL_PCAP->dlt, tmac, ETHERTYPE_ARP);
   ON_ERROR(t, -1, "ec_build_link_layer: %s", libnet_geterror(GBL_LNET->lnet));
   
   /* coalesce the pblocks */
   c = libnet_adv_cull_packet(GBL_LNET->lnet, &packet, &packet_s);
   ON_ERROR(c, -1, "libnet_adv_cull_packet: %s", libnet_geterror(GBL_LNET->lnet));
  
   /* send the packet */
   c = libnet_write(GBL_LNET->lnet);
   ON_ERROR(c, -1, "libnet_write (%d): %s", c, libnet_geterror(GBL_LNET->lnet));
   
   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet);

   /* free the packet */
   SAFE_FREE(packet);
   
   SEND_UNLOCK;
   
   return c;
}


/*
 * helper function to send out an ICMP ECHO packet
 */
int send_icmp_echo(u_char type, struct ip_addr *sip, u_int8 *smac, struct ip_addr *tip, u_int8 *tmac)
{
   libnet_ptag_t t = (libnet_ptag_t)pthread_self();
   int c;
 
   /* if not lnet warn the developer ;) */
   BUG_IF(GBL_LNET->lnet_L3 == 0);
   
   SEND_LOCK;

   /* create the ICMP header */
   t = libnet_build_icmpv4_echo(
           type,                    /* type */
           0,                       /* code */
           0,                       /* checksum */
           htons(EC_MAGIC_16),      /* identification number */
           htons(EC_MAGIC_16),      /* sequence number */
           NULL,                    /* payload */
           0,                       /* payload size */
           GBL_LNET->lnet_L3,       /* libnet handle */
           0);                      /* libnet id */
   ON_ERROR(t, -1, "libnet_build_arp: %s", libnet_geterror(GBL_LNET->lnet_L3));
  
   /* auto calculate the checksum */
   libnet_toggle_checksum(GBL_LNET->lnet_L3, t, 0);
  
   /* create the IP header */
   t = libnet_build_ipv4(                                                                          
           LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H,       /* length */                                    
           0,                                          /* TOS */                                       
           htons(EC_MAGIC_16),                         /* IP ID */                                     
           0,                                          /* IP Frag */                                   
           64,                                         /* TTL */                                       
           IPPROTO_ICMP,                               /* protocol */                                  
           0,                                          /* checksum */                                  
           *(u_long *)&(sip->addr),                    /* source IP */                                 
           *(u_long *)&(tip->addr),                    /* destination IP */                            
           NULL,                                       /* payload */                                   
           0,                                          /* payload size */                              
           GBL_LNET->lnet_L3,                          /* libnet handle */                             
           0);
   ON_ERROR(t, -1, "libnet_build_ipv4: %s", libnet_geterror(GBL_LNET->lnet_L3));
  
   /* auto calculate the checksum */
   libnet_toggle_checksum(GBL_LNET->lnet_L3, t, 0);
 
   /* send the packet to Layer 3 */
   c = libnet_write(GBL_LNET->lnet_L3);
   ON_ERROR(c, -1, "libnet_write (%d): %s", c, libnet_geterror(GBL_LNET->lnet_L3));

   /* clear the pblock */
   libnet_clear_packet(GBL_LNET->lnet_L3);

   SEND_UNLOCK;
   
   return c;
}

/*
 * register a builder in the table
 * a builder is a function to create a link layer header.
 */
void add_builder(u_int8 dlt, FUNC_BUILDER_PTR(builder))
{
   struct build_entry *e;

   SAFE_CALLOC(e, 1, sizeof(struct build_entry));
   
   e->dlt = dlt;
   e->builder = builder;

   SLIST_INSERT_HEAD(&builders_table, e, next); 
   
   return;
   
}

/*
 * build the header calling the registered
 * function for the current media
 */
libnet_ptag_t ec_build_link_layer(u_int8 dlt, u_int8 *dst, u_int16 proto)
{
   struct build_entry *e;

   SLIST_FOREACH (e, &builders_table, next) {
      if (e->dlt == dlt) {
         return e->builder(dst, proto);
      }
   }

   /* on error return -1 */
   return -1;
}

/* EOF */

// vim:ts=3:expandtab

