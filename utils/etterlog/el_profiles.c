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

    $Id: el_profiles.c,v 1.2 2003/04/05 09:25:10 alor Exp $
*/

#include <el.h>
#include <ec_log.h>
#include <ec_profiles.h>

/* globals */

LIST_HEAD(, host_profile) hosts_list_head;

/* protos */

void *get_host_list_ptr(void);
int profile_add_info(struct log_header_info *inf);
static void update_info(struct host_profile *h, struct log_header_info *inf);
static void update_port_list(struct host_profile *h, struct log_header_info *inf);
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

int profile_add_info(struct log_header_info *inf)
{
   struct host_profile *h;

   LIST_FOREACH(h, &hosts_list_head, next) {
      /* search the host.
       * it is identified by the mac and the ip address */
      if (!memcmp(h->L2_addr, inf->L2_addr, ETH_ADDR_LEN) &&
          !ip_addr_cmp(&h->L3_addr, &inf->L3_addr) ) {
         update_info(h, inf);
         /* the host was already in the list
          * return 0 host added */
         return 0;
      }
   }
  
   /* the host was not found, create a new entry */
   
   h = calloc(1, sizeof(struct host_profile));
   ON_ERROR(h, NULL, "can't allocate memory");

   update_info(h, inf);

   LIST_INSERT_HEAD(&hosts_list_head, h, next);
   
   return 1;   
}

/* set the info in a host profile */

static void update_info(struct host_profile *h, struct log_header_info *inf)
{
   memcpy(h->L2_addr, inf->L2_addr, ETH_ADDR_LEN);

   memcpy(&h->L3_addr, &inf->L3_addr, sizeof(struct ip_addr));

   h->distance = inf->distance;

   /* if it is marked as the gw, don't update */
   if (!(h->type & FP_GATEWAY))
      h->type = inf->type;
   /* 
    * if the type is FP_HOST_NONLOCAL 
    * search for the GW and mark it
    */
   if (h->type & FP_HOST_NONLOCAL)
      set_gateway(h->L2_addr);
      
   memcpy(h->fingerprint, inf->fingerprint, FINGER_LEN);

   /* add the open port */
   update_port_list(h, inf);
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
   
static void update_port_list(struct host_profile *h, struct log_header_info *inf)
{
   
}

/* EOF */

// vim:ts=3:expandtab

