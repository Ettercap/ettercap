/*
    link_type -- ettercap plugin -- Check the link type (hub\switch)

    it sends a spoofed arp request and waits for a reply

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
#include <ec_threads.h>
#include <ec_sleep.h>


/* globals */
#define LINK_HUB     0
#define LINK_SWITCH  1
u_char linktype;
struct hosts_list targets[2];

/* mutexes */
static pthread_mutex_t link_type_mutex = PTHREAD_MUTEX_INITIALIZER;

/* protos */
int plugin_load(void *);
static int link_type_init(void *);
static EC_THREAD_FUNC(link_type_thread);
static int link_type_fini(void *);
static void parse_arp(struct packet_object *po);

/* plugin operations */

struct plugin_ops link_type_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "link_type",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Check the link type (hub/switch)",  
   /* the plugin version. */ 
   .version =           "1.0",   
   /* activation function */
   .init =              &link_type_init,
   /* deactivation function */                     
   .fini =              &link_type_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   return plugin_register(handle, &link_type_ops);
}

/******************* STANDARD FUNCTIONS *******************/

static int link_type_init(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   ec_thread_new("link_type", "plugin link_type", 
         &link_type_thread, NULL);

   return PLUGIN_RUNNING;
}

static EC_THREAD_FUNC(link_type_thread)
{
   /* variable not used */
   (void) EC_THREAD_PARAM;

   u_char counter = 0;
   struct hosts_list *h;
   
   ec_thread_init();
   PLUGIN_LOCK(link_type_mutex);
   
   /* don't show packets while operating */
   EC_GBL_OPTIONS->quiet = 1;

   /* It doesn't work if unoffensive */
   if (EC_GBL_OPTIONS->unoffensive) {
      INSTANT_USER_MSG("link_type: plugin doesn't work in UNOFFENSIVE mode\n");
      PLUGIN_UNLOCK(link_type_mutex);
      plugin_kill_thread("link_type", "link_type");
      return PLUGIN_FINISHED;
   }

  /* Performs some checks */
   if (EC_GBL_PCAP->dlt != IL_TYPE_ETH) {
      INSTANT_USER_MSG("link_type: This plugin works only on ethernet networks\n\n");
      PLUGIN_UNLOCK(link_type_mutex);
      plugin_kill_thread("link_type", "link_type");
      return PLUGIN_FINISHED;
   }

   if (!EC_GBL_PCAP->promisc) {
      INSTANT_USER_MSG("link_type: You have to enable promisc mode to run this plugin\n\n");
      PLUGIN_UNLOCK(link_type_mutex);
      plugin_kill_thread("link_type", "link_type");
      return PLUGIN_FINISHED;
   }
   
   /* Take (if any) first two elements form the host list */
   LIST_FOREACH(h, &EC_GBL_HOSTLIST, next) {
      memcpy(&(targets[counter].ip), &h->ip, sizeof(struct ip_addr));
      memcpy(targets[counter].mac, h->mac, MEDIA_ADDR_LEN);
      counter++;
      if (counter == 2)
         break;
   }
   
   if (counter == 0) {
      INSTANT_USER_MSG("link_type: You have to build host list to run this plugin\n\n");
      PLUGIN_UNLOCK(link_type_mutex);
      plugin_kill_thread("link_type", "link_type");
      return PLUGIN_FINISHED;
   }

   /* 
    * If we have only one element in the host list 
    * use target mac address and our ip as source 
    */
   if (counter == 1) {   
      INSTANT_USER_MSG("link_type: Only one host in the list. Check will be less reliable\n\n"); 
      memcpy(&(targets[1].ip), &EC_GBL_IFACE->ip, sizeof(struct ip_addr));
      memcpy(targets[1].mac, targets[0].mac, MEDIA_ADDR_LEN);        
   }

   /* We assume switch by default */
   linktype = LINK_SWITCH;   

   INSTANT_USER_MSG("link_type: Checking link type...\n");
   
   /* Add the hook to collect ARP replies from the victim */
   hook_add(HOOK_PACKET_ARP, &parse_arp);

   /* Send bogus ARP request */
   send_arp(ARPOP_REQUEST, &(targets[1].ip), targets[1].mac, &(targets[0].ip), targets[0].mac);   
   
   /* wait for the response */
   ec_usleep(SEC2MICRO(1));

   /* remove the hook */
   hook_del(HOOK_PACKET_ARP, &parse_arp);

   INSTANT_USER_MSG("link_type: You are plugged into a ");
   if (linktype == LINK_SWITCH)
      INSTANT_USER_MSG("SWITCH\n\n");
   else
      INSTANT_USER_MSG("HUB\n\n");
      
   PLUGIN_UNLOCK(link_type_mutex);
   plugin_kill_thread("link_type", "link_type");
   return PLUGIN_FINISHED;
}


static int link_type_fini(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   pthread_t pid;

   pid = ec_thread_getpid("link_type");

   if (!pthread_equal(pid, EC_PTHREAD_NULL))
         ec_thread_destroy(pid);

   INSTANT_USER_MSG("link_type: plugin terminated...\n");

   return PLUGIN_FINISHED;
}

/*********************************************************/

/* Check if it's the reply to our bougs request */
static void parse_arp(struct packet_object *po)
{
   if (!memcmp(po->L2.dst, targets[1].mac, MEDIA_ADDR_LEN))
      linktype = LINK_HUB;
}


/* EOF */

// vim:ts=3:expandtab
 
