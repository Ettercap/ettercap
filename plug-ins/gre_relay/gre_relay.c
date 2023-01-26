/*
    gre_relay -- ettercap plugin -- Tunnel broker for redirected GRE tunnels

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

*/


#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_packet.h>
#include <ec_hook.h>
#include <ec_send.h>

struct ip_header {
#ifndef WORDS_BIGENDIAN
   u_int8   ihl:4;
   u_int8   version:4;
#else 
   u_int8   version:4;
   u_int8   ihl:4;
#endif
   u_int8   tos;
   u_int16  tot_len;
   u_int16  id;
   u_int16  frag_off;
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_FRAG 0x1fff
   u_int8   ttl;
   u_int8   protocol;
   u_int16  csum;
   u_int32  saddr;
   u_int32  daddr;
/*The options start here. */
};


#ifdef WITH_IPV6
struct ip6_header {
#ifndef WORDS_BIGENDIAN
   u_int8   version:4;
   u_int8   priority:4;
#else
   u_int8   priority:4;
   u_int8   version:4;
#endif
   u_int8   flow_lbl[3];
   u_int16  payload_len;
   u_int8   next_hdr;
   u_int8   hop_limit;

   u_int8   saddr[IP6_ADDR_LEN];
   u_int8   daddr[IP6_ADDR_LEN];
};

struct icmp6_nsol {
   u_int32 res;
   u_int8 target[IP6_ADDR_LEN];
};
#endif


/* globals */
struct ip_addr fake_ip;

/* protos */
int plugin_load(void *);
static int gre_relay_init(void *);
static int gre_relay_fini(void *);
static int gre_relay_unload(void *);

static void parse_gre(struct packet_object *po);
static void parse_arp(struct packet_object *po);

#ifdef WITH_IPV6
static void parse_nd(struct packet_object *po);
#endif

/* plugin operations */
struct plugin_ops gre_relay_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "gre_relay",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Tunnel broker for redirected GRE tunnels",  
   /* the plugin version. */ 
   .version =           "1.1",   
   /* activation function */
   .init =              &gre_relay_init,
   /* deactivation function */                     
   .fini =              &gre_relay_fini,
   /* clean-up function */
   .unload =            &gre_relay_unload,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   return plugin_register(handle, &gre_relay_ops);
}

/******************* STANDARD FUNCTIONS *******************/

static int gre_relay_init(void *dummy) 
{
   char tmp[MAX_ASCII_ADDR_LEN];

   /* variable not used */
   (void) dummy;

   /* It doesn't work if unoffensive */
   if (EC_GBL_OPTIONS->unoffensive) {
      INSTANT_USER_MSG("gre_relay: plugin doesn't work in UNOFFENSIVE mode\n");
      return PLUGIN_FINISHED;
   }

   /* don't display messages while operating */
   EC_GBL_OPTIONS->quiet = 1;

   memset(tmp, 0, sizeof(tmp));
   
   ui_input("Unused IP address: ", tmp, sizeof(tmp), NULL);

   /* convert IP string into ip_addr struct */
   if (ip_addr_pton(tmp, &fake_ip) != E_SUCCESS) {
      INSTANT_USER_MSG("gre_relay: Bad IP address\n");
      return PLUGIN_FINISHED;
   }

   USER_MSG("gre_relay: plugin running...\n");
   
   hook_add(HOOK_PACKET_GRE, &parse_gre);
   hook_add(HOOK_PACKET_ARP_RQ, &parse_arp);
#ifdef WITH_IPV6
   hook_add(HOOK_PACKET_ICMP6_NSOL, &parse_nd);
#endif

   return PLUGIN_RUNNING;      
}


static int gre_relay_fini(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   USER_MSG("gre_relay: plugin terminated...\n");

   hook_del(HOOK_PACKET_GRE, &parse_gre);
   hook_del(HOOK_PACKET_ARP_RQ, &parse_arp);
#ifdef WITH_IPV6
   hook_del(HOOK_PACKET_ICMP6_NSOL, &parse_nd);
#endif

   return PLUGIN_FINISHED;
}


static int gre_relay_unload(void *dummy)
{
   /* variable not used */
   (void) dummy;

   return PLUGIN_UNLOADED;
}

/*********************************************************/

/* Send back GRE packets */
static void parse_gre(struct packet_object *po)
{
   struct ip_header *iph;
#ifdef WITH_IPV6
   struct ip6_header *ip6h;
#endif
      
   /* Chek if this is a packet for our fake host */
   if (!(po->flags & PO_FORWARDABLE)) 
      return; 

   if ( ip_addr_cmp(&po->L3.dst, &fake_ip) )
      return;
      
   if ( po->L3.header == NULL)
      return;

   /* Switch source and dest IP address */
   switch (ntohs(po->L3.dst.addr_type)) {
      case AF_INET:
         iph = (struct ip_header*)po->L3.header;
         iph->daddr = iph->saddr;
         iph->saddr = fake_ip.addr32[0];
         /* Increase ttl */
         iph->ttl = 128;
         break;
#ifdef WITH_IPV6
      case AF_INET6:
         ip6h = (struct ip6_header*)po->L3.header;
         ip_addr_cpy(ip6h->daddr, &po->L3.src);
         ip_addr_cpy(ip6h->saddr, &fake_ip);
         /* Increase ttl */
         ip6h->hop_limit = 128;
         break;
#endif
      default:
         return;
   }
   

   po->flags |= PO_MODIFIED;
}


/* Reply to requests for our fake host */
static void parse_arp(struct packet_object *po)
{
   if (!ip_addr_cmp(&fake_ip, &po->L3.dst))
      send_arp(ARPOP_REPLY, &fake_ip, EC_GBL_IFACE->mac, &po->L3.src, po->L2.src);
}

#ifdef WITH_IPV6
/* Reply to requests for our IPv6 fake host */
static void parse_nd(struct packet_object *po)
{
   struct icmp6_nsol* nsol;
   struct ip_addr target;

   nsol = (struct icmp6_nsol*)po->L4.options;
   ip_addr_init(&target, AF_INET6, (u_char*)nsol->target);

   if (!ip_addr_cmp(&fake_ip, &target))
      send_L2_icmp6_nadv(&fake_ip, &po->L3.src, EC_GBL_IFACE->mac, 0, po->L2.src);
}
#endif

/* EOF */

// vim:ts=3:expandtab
 
