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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_dissect.c,v 1.5 2003/06/28 08:08:00 alor Exp $
*/

#include <ec.h>
#include <ec_dissect.h>
#include <ec_packet.h>

/* globals */

static SLIST_HEAD (, dissect_entry) dissect_list;

struct dissect_entry {
   char *name;
   u_int32 type;
   u_int8 level;
   FUNC_DECODER_PTR(decoder);
   SLIST_ENTRY (dissect_entry) next;
};

/* protos */

void dissect_add(char *name, u_int8 level, u_int32 port, FUNC_DECODER_PTR(decoder));
int dissect_modify(int mode, char *name, u_int32 port);

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
  
   /* 
    * is this ident from our level ?
    * check the magic !
    */
   if (ids->magic != id->magic)
      return 0;
   
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
  
   /* the magic */
   ident->magic = DISSECT_MAGIC;
      
   /* prepare the ident */
   memcpy(&ident->L3_src, &po->L3.src, sizeof(struct ip_addr));
   memcpy(&ident->L3_dst, &po->L3.dst, sizeof(struct ip_addr));
   
   ident->L4_proto = po->L4.proto;
   
   ident->L4_src = po->L4.src;
   ident->L4_dst = po->L4.dst;

   /* return the ident */
   *i = ident;
}


/*
 * register a dissector in the dissectors list
 * and add it to the decoder list.
 * this list i used by dissect_modify during the parsing
 * of etter.conf to enable/disable the dissectors via their name.
 */

void dissect_add(char *name, u_int8 level, u_int32 port, FUNC_DECODER_PTR(decoder))
{
   struct dissect_entry *e;

   e = calloc(1, sizeof(struct dissect_entry));
   ON_ERROR(e, NULL, "can't allocate memory");

   e->name = strdup(name);
   e->level = level;
   e->type = port;
   e->decoder = decoder;

   SLIST_INSERT_HEAD (&dissect_list, e, next); 

   /* add the default decoder */
   add_decoder(level, port, decoder);
      
   return;
}

/*
 * given the name of the dissector add or remove it 
 * from the decoders' table.
 * is it possible to add multiple port with MODE_ADD
 */

int dissect_modify(int mode, char *name, u_int32 port)
{
   struct dissect_entry *e;

   SLIST_FOREACH (e, &dissect_list, next) {
      if (!strcasecmp(e->name, name)) {
         switch (mode) {
            case MODE_ADD:
               DEBUG_MSG("dissect_modify: %s added on %d", name, port);
               /* add in the lists */
               dissect_add(e->name, e->level, port, e->decoder);
               add_decoder(e->level, port, e->decoder);
               return ESUCCESS;
               break;
            case MODE_REP:
               /* no modifications needed */
               if (e->type == port)
                  return ESUCCESS;

               DEBUG_MSG("dissect_modify: %s replaced from %d to %d", name, e->type, port);
               del_decoder(e->level, e->type);
               /* a value of 0 will disable the dissector */
               if (port == 0)
                  return ESUCCESS;
              
               /* replace with the new value */
               add_decoder(e->level, port, e->decoder);
               e->type = port;
               return ESUCCESS;
               break;
         }
      }
   }

   return -ENOTFOUND;
}


/* EOF */

// vim:ts=3:expandtab

