/*
    ettercap -- host profiling module

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

    $Id: ec_profiles.c,v 1.8 2003/07/04 21:51:38 alor Exp $
*/

#include <ec.h>
#include <ec_passive.h>
#include <ec_profiles.h>
#include <ec_packet.h>
#include <ec_hook.h>

/* protos */

void __init profiles_init(void);
void profile_parse(struct packet_object *po);
static int profile_add_host(struct packet_object *po);
static int profile_add_user(struct packet_object *po);
static void update_info(struct host_profile *h, struct packet_object *po);
static void update_port_list(struct host_profile *h, struct packet_object *po);
static void set_gateway(u_char *L2_addr);

/************************************************/
  
/*
 * add the hook function
 */
void __init profiles_init(void)
{
   /* add the hook for the ARP packets */
   hook_add(PACKET_ARP, &profile_parse);
   
   /* add the hook for ICMP packets */
   hook_add(PACKET_ICMP, &profile_parse);
         
   /* receive all the top half packets */
   hook_add(HOOK_DISPATCHER, &profile_parse);
}


/*
 * decides if the packet has to be added
 * to the profiles
 */
void profile_parse(struct packet_object *po)
{
   /*
    * call the add function only if the packet
    * is interesting...
    * we don't want to log conversations, only
    * open ports, OSes etc etc ;)
    */
   if ( po->L3.proto == htons(LL_TYPE_ARP) ||                     /* arp packets */
        po->L4.proto == NL_TYPE_ICMP ||                           /* icmp packets */
        is_open_port(po->L4.proto, po->L4.src, po->L4.flags) ||   /* src port is open */
        strcmp(po->PASSIVE.fingerprint, "") ||                    /* collected fingerprint */  
        po->DISSECTOR.banner                                      /* banner */
      )
      profile_add_host(po);

   /* 
    * usernames and passwords are to be bound to 
    * destination host, not source.
    * do it here, search for the right host and add
    * the username to the right port.
    */
   if ( po->DISSECTOR.user ||                               /* user */
        po->DISSECTOR.pass ||                               /* pass */
        po->DISSECTOR.info                                  /* info */
      )
      profile_add_user(po);
   
   return;
}


/* 
 * add the infos to the profiles tables
 * return the number of hosts added (1 if added, 0 if updated)
 */
static int profile_add_host(struct packet_object *po)
{
   struct host_profile *h;
   struct host_profile *c;
   struct host_profile *last = NULL;

   /* 
    * if the type is FP_HOST_NONLOCAL 
    * search for the GW and mark it
    */
   if (po->PASSIVE.flags & FP_HOST_NONLOCAL) {
      set_gateway(po->L2.src);
      /* the mac address of non local should not be saved */
      memset(&po->L2.src, 0, ETH_ADDR_LEN);
   }

   /* parse the list */
   LIST_FOREACH(h, &GBL_PROFILES, next) {
      /* search the host.
       * it is identified by the mac and the ip address */
      if (!memcmp(h->L2_addr, po->L2.src, ETH_ADDR_LEN) &&
          !ip_addr_cmp(&h->L3_addr, &po->L3.src) ) {
         update_info(h, po);
         /* the host was already in the list
          * return 0 host added */
         return 0;
      }
   }
  
   DEBUG_MSG("profile_add_host");
   
   /* 
    * the host was not found, create a new entry 
    * before the creation check if it has to be stored...
    */
   
   /* this is a local and we want only remote */
   if ((po->PASSIVE.flags & FP_HOST_LOCAL) && GBL_OPTIONS->only_remote)
      return 0;
   
   /* this is remote and we want only local */
   if ((po->PASSIVE.flags & FP_HOST_NONLOCAL) && GBL_OPTIONS->only_local)
      return 0;
   
   /* create the new host */
   h = calloc(1, sizeof(struct host_profile));
   ON_ERROR(h, NULL, "can't allocate memory");

   /* fill the structure with the collected infos */
   update_info(h, po);
   
   /* search the right point to inser it (ordered ascending) */
   LIST_FOREACH(c, &GBL_PROFILES, next) {
      if ( ip_addr_cmp(&c->L3_addr, &h->L3_addr) > 0 )
         break;
      last = c;
   }
   
   if (LIST_FIRST(&GBL_PROFILES) == NULL) 
      LIST_INSERT_HEAD(&GBL_PROFILES, h, next);
   else if (c != NULL) 
      LIST_INSERT_BEFORE(c, h, next);
   else 
      LIST_INSERT_AFTER(last, h, next);

   return 1;   
}

/* set the info in a host profile */

static void update_info(struct host_profile *h, struct packet_object *po)
{
   
   /* if it is marked as the gateway or unkown, don't update */
   if ( !(h->type & FP_GATEWAY) && !(h->type & FP_UNKNOWN) )
      h->type = po->PASSIVE.flags;
   
   /* update the mac address only if local or unknown */
   if (h->type & FP_HOST_LOCAL || h->type == FP_UNKNOWN)
      memcpy(h->L2_addr, po->L2.src, ETH_ADDR_LEN);
   
   /* the ip address */
   memcpy(&h->L3_addr, &po->L3.src, sizeof(struct ip_addr));

   /* the distance in HOP */
   if (po->L3.ttl > 1)
      h->distance = TTL_PREDICTOR(po->L3.ttl) - po->L3.ttl + 1;
   else
      h->distance = po->L3.ttl;
      
   /* get the hostname */
   host_iptoa(&po->L3.src, h->hostname);
   
   /* 
    * update the fingerprint only if there isn't a previous one
    * or if the previous fingerprint was an ACK
    * fingerprint. SYN fingers are more reliable
    */
   if (po->PASSIVE.fingerprint[FINGER_TCPFLAG] != '\0' &&
        (h->fingerprint[FINGER_TCPFLAG] == '\0' || 
         h->fingerprint[FINGER_TCPFLAG] == 'A') )
      memcpy(h->fingerprint, po->PASSIVE.fingerprint, FINGER_LEN);

   /* add the open port */
   update_port_list(h, po);
}


/* 
 * search the host with this L2_addr
 * and mark it as the GW
 */

static void set_gateway(u_char *L2_addr)
{
   struct host_profile *h;

   LIST_FOREACH(h, &GBL_PROFILES, next) {
      if (!memcmp(h->L2_addr, L2_addr, ETH_ADDR_LEN) ) {
         h->type |= FP_GATEWAY; 
         return;
      }
   }
}

/* 
 * update the list of open ports
 */
   
static void update_port_list(struct host_profile *h, struct packet_object *po)
{
   struct open_port *o;
   struct open_port *p;
   struct open_port *last = NULL;

   /* search for an existing port */
   LIST_FOREACH(o, &(h->open_ports_head), next) {
      if (o->L4_proto == po->L4.proto && o->L4_addr == po->L4.src) {
         /* set the banner for the port */
         if (o->banner == NULL && po->DISSECTOR.banner)
            o->banner = po->DISSECTOR.banner;
         /* already logged */
         return;
      }
   }
  
   /* skip this port, the packet was logged for
    * another reason, not the open port */
   //if ( !is_open_src_port(po) && !is_open_dst_port(po))
   if ( !is_open_port(po->L4.proto, po->L4.src, po->L4.flags) )
      return;

   /* create a new entry */
   
   o = calloc(1, sizeof(struct open_port));
   ON_ERROR(o, NULL, "can't allocate memory");

   o->L4_proto = po->L4.proto;
   o->L4_addr = po->L4.src;
   
   /* search the right point to inser it (ordered ascending) */
   LIST_FOREACH(p, &(h->open_ports_head), next) {
      if ( ntohs(p->L4_addr) > ntohs(o->L4_addr) )
         break;
      last = p;
   }

   /* insert in the right position */
   if (LIST_FIRST(&(h->open_ports_head)) == NULL) 
      LIST_INSERT_HEAD(&(h->open_ports_head), o, next);
   else if (p != NULL) 
      LIST_INSERT_BEFORE(p, o, next);
   else 
      LIST_INSERT_AFTER(last, o, next);
   
}

/* 
 * update the users list
 */

static int profile_add_user(struct packet_object *po)
{
   struct host_profile *h;
   struct open_port *o = NULL;
   struct active_user *u;
   struct active_user *a;
   struct active_user *last = NULL;
   int found = 0;

   /* no info to update */
   if (po->DISSECTOR.user == NULL || po->DISSECTOR.pass == NULL)
      return 0;
  
   DEBUG_MSG("profile_add_user");
   
   /* search the right port on the right host */
   LIST_FOREACH(h, &GBL_PROFILES, next) {
      
      /* right host */
      if ( !ip_addr_cmp(&h->L3_addr, &po->L3.dst) ) {
      
         LIST_FOREACH(o, &(h->open_ports_head), next) {
            /* right port and proto */
            if (o->L4_proto == po->L4.proto && o->L4_addr == po->L4.dst) {
               found = 1;
               break;
            }
         }
      }
      /* if already found, exit the loop */
      if (found) 
         break;
   }
   
   /* 
    * the port was not found... possible ?
    * yes, but extremely rarely.
    * don't worry, we have lost this for now, 
    * but the next time it will be captured.
    */
   if (!found || o == NULL)
      return 0;
   
   /* search if the user was already logged */ 
   LIST_FOREACH(u, &(o->users_list_head), next) {
      if (!strcmp(u->user, po->DISSECTOR.user) && 
          !strcmp(u->pass, po->DISSECTOR.pass))
         return 0;
   }
   
   u = calloc(1, sizeof(struct active_user));
   ON_ERROR(u, NULL, "can't allocate memory");

   /* if there are infos copy it, else skip */
   if (po->DISSECTOR.user && po->DISSECTOR.pass) {
      u->user = po->DISSECTOR.user;
      u->pass = po->DISSECTOR.pass;
   } else {
      SAFE_FREE(u);
      return 0;
   }
  
   if (po->DISSECTOR.info)
      u->info = po->DISSECTOR.info;
  
   /* search the right point to inser it (ordered alphabetically) */
   LIST_FOREACH(a, &(o->users_list_head), next) {
      if ( strcmp(a->user, u->user) > 0 )
         break;
      last = a;
   }
   
   /* insert in the right position */
   if (LIST_FIRST(&(o->users_list_head)) == NULL) 
      LIST_INSERT_HEAD(&(o->users_list_head), u, next);
   else if (a != NULL) 
      LIST_INSERT_BEFORE(a, u, next);
   else 
      LIST_INSERT_AFTER(last, u, next);
   
   return 1;
}


/* EOF */

// vim:ts=3:expandtab

