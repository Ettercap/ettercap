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

    $Id: el_profiles.c,v 1.1 2003/04/03 21:18:03 alor Exp $
*/

#include <el.h>
#include <ec_log.h>
#include <ec_profiles.h>

/* globals */

static LIST_HEAD(, host_profile) hosts_list_head;

/* protos */

int profile_add_info(struct log_header_info *inf);
static void update_info(struct host_profile *h);

/************************************************/
 
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
         update_info(h);
         /* the host was already in the list
          * return 0 host added */
         return 0;
      }
   }
   
   h = calloc(1, sizeof(struct host_profile));
   ON_ERROR(h, NULL, "can't allocate memory");

   update_info(h);

   LIST_INSERT_HEAD(&hosts_list_head, h, next);
   
   return 1;   
}

/* set the info in a host profile */

static void update_info(struct host_profile *h)
{

}

/* EOF */

// vim:ts=3:expandtab

