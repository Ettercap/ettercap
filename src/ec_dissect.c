/*
    ettercap -- dissector module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_dissect.c,v 1.2 2003/04/14 21:05:14 alor Exp $
*/

#include <ec.h>
#include <ec_dissect.h>
#include <ec_packet.h>

/* globals */


/* protos */

int dissect_match(void *id_sess, void *id_curr);
void dissect_create_session(struct session **s, struct packet_object *po);
void dissect_create_ident(void **i, struct packet_object *po);            

/*******************************************/

/*
 * compare two session ident
 *
 * return 1 if it matches
 */

int dissect_match(void *id_sess, void *id_curr)
{
   struct dissect_ident *ids = id_sess;
   struct dissect_ident *id = id_curr;

   /* sanity check */
   BUG_IF(ids, NULL);
   BUG_IF(id, NULL);
   
   /* check the protocol */
   if (ids->L4_proto != id->L4_proto)
      return 0;

   /* from source to dest */
   if (ids->L4_src == id->L4_src &&
       ids->L4_dst == id->L4_dst &&
       !ip_addr_cmp(&ids->L3_src, &id->L3_src) &&
       !ip_addr_cmp(&ids->L3_dst, &id->L3_dst) )
      return 1;
   
   /* from dest to source */
   if (ids->L4_src == id->L4_dst &&
       ids->L4_dst == id->L4_src &&
       !ip_addr_cmp(&ids->L3_src, &id->L3_dst) &&
       !ip_addr_cmp(&ids->L3_dst, &id->L3_src) )
      return 1;

   return 0;
}


/*
 * prepare the ident and the pointer to match function
 * for a dissector
 */

void dissect_create_session(struct session **s, struct packet_object *po)
{
   void *ident;

   /* create the ident */
   dissect_create_ident(&ident, po);
   
   /* allocate the session */
   *s = calloc(1, sizeof(struct session));
   ON_ERROR(*s, NULL, "can't allocate memory");
   
   /* link to the session */
   (*s)->ident = ident;
   
   /* the matching function */
   (*s)->match = &dissect_match;
}

/*
 * create the ident for a session
 */

void dissect_create_ident(void **i, struct packet_object *po)
{
   struct dissect_ident *ident = *i;
   
   /* allocate the ident for that session */
   ident = calloc(1, sizeof(struct dissect_ident));
   ON_ERROR(ident, NULL, "can't allocate memory");
   
   /* prepare the ident */
   memcpy(&ident->L3_src, &po->L3.src, sizeof(struct ip_addr));
   memcpy(&ident->L3_dst, &po->L3.dst, sizeof(struct ip_addr));
   
   ident->L4_proto = po->L4.proto;
   
   ident->L4_src = po->L4.src;
   ident->L4_dst = po->L4.dst;

   /* return the ident */
   *i = ident;
}

/* EOF */

// vim:ts=3:expandtab

