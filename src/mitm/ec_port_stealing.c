/*
    ettercap -- Port Stealing mitm module

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

    $Id: ec_port_stealing.c,v 1.2 2003/12/13 20:08:30 lordnaga Exp $
*/

#include <ec.h>
#include <ec_mitm.h>
#include <ec_send.h>
#include <ec_threads.h>
#include <ec_ui.h>
#include <ec_strings.h>

/* globals */

struct steal_list {
   struct ip_addr ip;
   u_char mac[MEDIA_ADDR_LEN];
   u_char wait_reply;
   LIST_HEAD(, packet_list) packet_table;
   LIST_ENTRY(steal_list) next;
};

LIST_HEAD(, steal_list) steal_table;
static int steal_tree;

struct eth_header
{
   u_int8   dha[ETH_ADDR_LEN];       /* destination eth addr */
   u_int8   sha[ETH_ADDR_LEN];       /* source ether addr */
   u_int16  proto;                   /* packet type ID field */
};

struct arp_header {
   u_int16  ar_hrd;          /* Format of hardware address.  */
   u_int16  ar_pro;          /* Format of protocol address.  */
   u_int8   ar_hln;          /* Length of hardware address.  */
   u_int8   ar_pln;          /* Length of protocol address.  */
   u_int16  ar_op;           /* ARP opcode (command).  */
#define ARPOP_REQUEST   1    /* ARP request.  */
};

#define FAKE_PCK_LEN sizeof(eth_header)+sizeof(arp_header)+sizeof(arp_eth_header)
struct packet_object fake_po;
char fake_pck[FAKE_PCK_LEN];

/* protos */

void port_stealing_init(void);
EC_THREAD_FUNC(port_stealer);
static void port_stealing_start(char *args);
static void port_stealing_stop(void);
static void parse_received(struct packet_object *po);
static void put_queue(struct packet_object *po);
static void send_queue(struct packet_object *po);


/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered mitm
 */

void __init port_stealing_init(void)
{
   struct mitm_method mm;

   mm.name = "port";
   mm.start = &port_stealing_start;
   mm.stop = &port_stealing_stop;
   
   mitm_add(&mm);
}


/*
 * init the PORT STEALING attack
 */
static void port_stealing_start(char *args)
{     
   struct hosts_list *h;
   struct steal_list *s;
   struct eth_header *heth;
   struct arp_header *harp;
   char bogus_mac[6]="\x00\xe7\x7e\xe7\x7e\xe7";
   
   DEBUG_MSG("port_stealing_start");

   steal_tree = 0;

   /* parse the args only if not empty */
   if (strcmp(args, "")) {
      for (p = strsep(&args, ","); p != NULL; p = strsep(&args, ",")) {
         if (!strcasecmp(p, "remote")) {
            /* 
            * allow sniffing of remote host even 
            * if the target is local (used for gw)
            */
            GBL_OPTIONS->remote = 1;
         } else if (!strcasecmp(p, "tree")) {
            steal_tree = 1; 
         } else {
            FATAL_ERROR("Port Stealing: paramenter incorrect.\n");
         }
      }
   }
 
   /* Port Stealing works only on ethernet switches */
   if (GBL_PCAP->dlt != IL_TYPE_ETH)
      FATAL_ERROR("Port Stealing does not support this media.\n");

   if (LIST_EMPTY(&GBL_HOSTLIST)) 
      USER_MSG("Host List is empty - No host for Port Stealing\n\n"); 

   /* Create the port stealing list from hosts list */   
   LIST_FOREACH(h, &GBL_HOSTLIST, next) {
      /* create the element and insert it in steal lists */
      SAFE_CALLOC(s, 1, sizeof(struct steal_list));
      memcpy(&s->ip, &h->ip, sizeof(struct ip_addr));
      memcpy(s->mac, h->mac, MEDIA_ADDR_LEN);
      LIST_INSERT_HEAD(&steal_table, s, next);
   }

   /* Create the packet that will be sent for stealing. 
    * This is a fake ARP request. 
    */
   heth = (struct eth_header *)fake_pck;
   harp = (struct arp_header)(heth + 1);

   if (steal_tree)
      memcpy(heth->dha, bogus_mac, ETH_ADDR_LEN);
   else
      memcpy(heth->dha, GBL_IFACE->mac, ETH_ADDR_LEN);

   heth->proto = htons();
   harp->ar_hrd = htons();
   harp->ar_pro = htons();
   harp->ar_hln = 6;
   harp->ar_pln = 4;
   harp->ar_op  = htons(ARPOP_REQUEST);

   packet_create_object(&fake_po, fake_pck, FAKE_PCK_LEN);
   
   /* Add the hooks:
    * - handle stealed packets (send arp request, stop stealing)
    * - put the packet in the send queue after "filtering"
    * - send the queue on arp reply (port restored, restart stealing)
    */
   hook_add(HOOK_PACKET_ETH, &parse_received);
   hook_add(HOOK_PRE_FORWARD, &put_queue);
   hook_add(HOOK_PACKET_ARP_RP, &send_queue);
   
   /* create the stealing thread */
   ec_thread_new("port_stealer", "Port Stealing module", &port_stealer, NULL);
}


/*
 * shut down the poisoning process
 */
static void port_stealing_stop(void)
{
   pthread_t pid;
   
   DEBUG_MSG("port_stealing_stop");
   
   /* destroy the poisoner thread */
   pid = ec_thread_getpid("port_stealer");
   
   /* the thread is active or not ? */
   if (pid != 0)
      ec_thread_destroy(pid);
   else
      return;
        
   USER_MSG("Prot Stealing deactivated.\n");
   USER_MSG("Restoring Switch tables...\n");
  
   ui_msg_flush(2);
   
   /* Remove the Hooks */
   hook_del(HOOK_PACKET_ETH, &parse_received);
   hook_del(HOOK_PRE_FORWARD, &put_queue);
   hook_del(HOOK_PACKET_ARP_RP, &send_queue);

   /* XXX - (mutex lock) Restore Switch Tables (2 times) */
   /* XXX - Free the stealing list (mutex unlock) */
}


/*
 * the real Port Stealing thread
 */
EC_THREAD_FUNC(port_stealer)
{
   struct steal_list *s;
   struct eth_header *heth;
   
   /* init the thread and wait for start up */
   ec_thread_init();
  
   heth = (struct eth_header *)fake_pck;
  
   /* never ending loop */
   LOOP {
      
      CANCELLATION_POINT();
      
      /* walk the list and steal the ports */
      LIST_FOREACH(s, &steal_table, next) {
         /* steal only ports for hosts where no packet is in queue */
         if (!s->wait_reply) {
            memcpy(heth->sha, s->mac, ETH_ADDR_LEN);
            send_L2(&fake_po); 
            //usleep(GBL_CONF->arp_storm_delay * 1000);  
         }
      }      
      //usleep(GBL_CONF->arp_storm_delay * 1000);
   }
   
   return NULL; 
}

static void parse_received(struct packet_object *po)
{
}

static void put_queue(struct packet_object *po)
{
}

static void send_queue(struct packet_object *po)
{
}


/* EOF */

// vim:ts=3:expandtab

