/*
    etterlog -- host profiling module

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

    $Id: el_profiles.c,v 1.3 2003/04/05 13:11:10 alor Exp $
*/

#include <el.h>
#include <ec_log.h>
#include <ec_profiles.h>

/* globals */

LIST_HEAD(, host_profile) hosts_list_head;

/* protos */

void *get_host_list_ptr(void);
int profile_add_info(struct log_header_info *inf, struct dissector_info *buf);
static void update_info(struct host_profile *h, struct log_header_info *inf, struct dissector_info *buf);
static void update_port_list(struct host_profile *h, struct log_header_info *inf, struct dissector_info *buf);
static void update_user_list(struct open_port *o, struct log_header_info *inf, struct dissector_info *buf);
static void set_gateway(u_char *L2_addr);

/************************************************/

/*
 * return the pointer to the host list
 */

void *get_host_list_ptr(void)
{
   return &hosts_list_head;
}

/* 
 * creates or updates the host list
 * return the number of hosts added (1 if added, 0 if updated)
 */

int profile_add_info(struct log_header_info *inf, struct dissector_info *buf)
{
   struct host_profile *h;

   /* 
    * if the type is FP_HOST_NONLOCAL 
    * search for the GW and mark it
    */
   if (inf->type & FP_HOST_NONLOCAL)
      set_gateway(inf->L2_addr);

   /* non local ip address must not carry mac address */
   if (inf->type & FP_HOST_NONLOCAL)
      memset(inf->L2_addr, 0, ETH_ADDR_LEN);
   
   /* parse the list */
   LIST_FOREACH(h, &hosts_list_head, next) {
      /* search the host.
       * it is identified by the mac and the ip address */
      if (!memcmp(h->L2_addr, inf->L2_addr, ETH_ADDR_LEN) &&
          !ip_addr_cmp(&h->L3_addr, &inf->L3_addr) ) {
         update_info(h, inf, buf);
         /* the host was already in the list
          * return 0 host added */
         return 0;
      }
   }
  
   /* the host was not found, create a new entry */
   
   h = calloc(1, sizeof(struct host_profile));
   ON_ERROR(h, NULL, "can't allocate memory");

   update_info(h, inf, buf);

   LIST_INSERT_HEAD(&hosts_list_head, h, next);
   
   return 1;   
}

/* set the info in a host profile */

static void update_info(struct host_profile *h, struct log_header_info *inf, struct dissector_info *buf)
{
   
   /* if it is marked as the gw, don't update */
   if (!(h->type & FP_GATEWAY))
      h->type = inf->type;
   
   /* update the mac address only if local */
   if (h->type & FP_HOST_LOCAL)
      memcpy(h->L2_addr, inf->L2_addr, ETH_ADDR_LEN);
   
   /* the ip address */
   memcpy(&h->L3_addr, &inf->L3_addr, sizeof(struct ip_addr));

   /* the distance in HOP */
   if (h->distance == 0)
      h->distance = inf->distance;

   /* 
    * update the fingerprint only there isn't a previous one
    * or if the previous fingerprint was an ACK
    * fingerprint. SYN fingers are more reliable
    */
   if (inf->fingerprint[FINGER_TCPFLAG] != '\0' &&
        (h->fingerprint[FINGER_TCPFLAG] == '\0' || 
         h->fingerprint[FINGER_TCPFLAG] == 'A') )
      memcpy(h->fingerprint, inf->fingerprint, FINGER_LEN);

   /* add the open port */
   update_port_list(h, inf, buf);
}


/* 
 * search the host with this L2_addr
 * and mark it as the GW
 */

static void set_gateway(u_char *L2_addr)
{
   struct host_profile *h;

   LIST_FOREACH(h, &hosts_list_head, next) {
      if (!memcmp(h->L2_addr, L2_addr, ETH_ADDR_LEN) ) {
         h->type |= FP_GATEWAY; 
         return;
      }
   }
}

/* 
 * update the list of open ports
 * and add the user and pass infos
 */
   
static void update_port_list(struct host_profile *h, struct log_header_info *inf, struct dissector_info *buf)
{
   struct open_port *o;

   /* search for an existing port */
   LIST_FOREACH(o, &(h->open_ports_head), next) {
      if (o->L4_proto == inf->L4_proto && o->L4_addr == inf->L4_addr) {
         update_user_list(o, inf, buf);
         return;
      }
   }
  
   /* skip this port, the packet was logged for
    * another reason, not the open port */
   if (inf->L4_addr == 0)
      return;

   /* create a new entry */
   
   o = calloc(1, sizeof(struct open_port));
   ON_ERROR(o, NULL, "can't allocate memory");

   o->L4_proto = inf->L4_proto;
   o->L4_addr = inf->L4_addr;
   
   /* insert in the list */
   LIST_INSERT_HEAD(&(h->open_ports_head), o, next);

   /* add user and pass */
   update_user_list(o, inf, buf);
}


static void update_user_list(struct open_port *o, struct log_header_info *inf, struct dissector_info *buf)
{
   struct active_user *u;

   /* search for an existing user and pass */
   LIST_FOREACH(u, &(o->users_list_head), next) {
      if (!strcmp(u->user, buf->user) && !strcmp(u->pass, buf->pass)) {
         return;
      }
   }
   
   u = calloc(1, sizeof(struct active_user));
   ON_ERROR(u, NULL, "can't allocate memory");

   /* if there are infos copy it, else skip */
   if (buf->user && buf->pass) {
      u->user = strdup(buf->user);
      u->pass = strdup(buf->pass);
   } else {
      SAFE_FREE(u);
      return;
   }
  
   if (buf->info)
      u->info = strdup(buf->info);
   
   LIST_INSERT_HEAD(&(o->users_list_head), u, next);
     
}



/* EOF */

// vim:ts=3:expandtab

