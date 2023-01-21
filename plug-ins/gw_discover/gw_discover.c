/*
    gw_discover -- ettercap plugin -- find the lan gateway

    it sends a syn to a remote ip with the mac address of a local host. 
    if the reply comes back, we have found the gateway 

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
#include <ec_sleep.h>


/* globals */

static struct ip_addr ip;
static u_int16 port;

/* protos */
int plugin_load(void *);
static int gw_discover_init(void *);
static int gw_discover_fini(void *);
static int gw_discover_unload(void *);

static int get_remote_target(struct ip_addr *ip, u_int16 *port);
static void do_discover(void);
static void get_replies(struct packet_object *po);

/* plugin operations */

struct plugin_ops gw_discover_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "gw_discover",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Try to find the LAN gateway",  
   /* the plugin version. */ 
   .version =           "1.0",   
   /* activation function */
   .init =              &gw_discover_init,
   /* deactivation function */                     
   .fini =              &gw_discover_fini,
   /* clean-up function */
   .unload =            &gw_discover_unload,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   return plugin_register(handle, &gw_discover_ops);
}

/******************* STANDARD FUNCTIONS *******************/

static int gw_discover_init(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   /* don't show packets while operating */
   EC_GBL_OPTIONS->quiet = 1;
   
   /* wipe the global vars */
   memset(&ip, 0, sizeof(struct ip_addr));

   if (get_remote_target(&ip, &port) == E_SUCCESS) {
      /* do the actual finterprinting */
      do_discover();   
   }
   
   return PLUGIN_FINISHED;
}


static int gw_discover_fini(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   return PLUGIN_FINISHED;
}

static int gw_discover_unload(void *dummy)
{
   /* variable not used */
   (void) dummy;

   return PLUGIN_UNLOADED;
}

/*********************************************************/


/* 
 * get the remote ip from user input 
 */
static int get_remote_target(struct ip_addr *p_ip, u_int16 *p_port)
{
   char input[MAX_ASCII_ADDR_LEN + 1 + 5 + 1];
   char ipstr[MAX_ASCII_ADDR_LEN];

   memset(input, 0, sizeof(input));
   
   /* get the user input */
   ui_input("Insert remote IP:PORT : ", input, sizeof(input), NULL);

   /* no input was entered */
   if (strlen(input) == 0)
      return -E_INVALID;
   
   /* get the hostname */
   if (ec_strsplit_ipport(input, ipstr, p_port))
      return -E_INVALID;

   /* convert IP string into ip_addr struct */
   if (ip_addr_pton(ipstr, p_ip))
      return -E_INVALID;

   /* correct parsing */
   if (*p_port != 0)
      return E_SUCCESS;

   return -E_INVALID;
}


/*
 * send the SYN packet to the target
 */
static void do_discover(void)
{
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   struct hosts_list *h;
   
   /* convert the in ascii ip address */
   ip_addr_ntoa(&ip, tmp);

   /* add the hook to collect tcp SYN+ACK packets */
   hook_add(HOOK_PACKET_TCP, &get_replies);
   
   INSTANT_USER_MSG("\nRemote target is %s:%d...\n\n", tmp, port);
      
   LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
      
      INSTANT_USER_MSG("Sending the SYN packet to %-15s [%s]\n", ip_addr_ntoa(&h->ip, tmp), mac_addr_ntoa(h->mac, tmp2));
      
      /* send the syn packet */
      send_tcp_ether(h->mac, &EC_GBL_IFACE->ip, &ip, htons(EC_MAGIC_16), htons(port), 0xabadc0de, 0xabadc0de, TH_SYN);
   }
  
   /* wait some time for slower replies */
   ec_usleep(SEC2MICRO(3));
   
   INSTANT_USER_MSG("\n");

   /* remove the hook */
   hook_del(HOOK_PACKET_TCP, &get_replies);

}

/*
 * collect the SYN+ACK replies
 */
static void get_replies(struct packet_object *po)
{
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   struct hosts_list *h;
   
   /* skip non syn ack packets */
   if ( !(po->L4.flags & (TH_SYN | TH_ACK)) )
      return;
 
   /* the source ip is diffent */
   if ( ip_addr_cmp(&po->L3.src, &ip))
      return;

   /* this is not the requested connection */
   if (po->L4.src != htons(port) || po->L4.dst != htons(EC_MAGIC_16))
      return;

   /* search the source mac address in the host list */
   LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
      if (!memcmp(po->L2.src, h->mac, MEDIA_ADDR_LEN)) {
         INSTANT_USER_MSG("[%s] %s is probably a gateway for the LAN\n", mac_addr_ntoa(po->L2.src, tmp2), ip_addr_ntoa(&h->ip, tmp));
      }
   }
   
}

/* EOF */

// vim:ts=3:expandtab
 
