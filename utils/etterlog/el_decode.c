/*
    etterlog -- decode a stream and extract file from it

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

    $Id: el_decode.c,v 1.3 2004/10/11 14:55:49 alor Exp $
*/


#include <el.h>
#include <el_functions.h>

/* globals */

static SLIST_HEAD (, dec_entry) extractor_table;

struct dec_entry {
   u_int8 level;
   u_int32 type;
   FUNC_EXTRACTOR_PTR(extractor);
   SLIST_ENTRY (dec_entry) next;
};

/* protos */

int decode_stream(struct stream_object *so);

void add_extractor(u_int8 level, u_int32 type, FUNC_EXTRACTOR_PTR(extractor));
void * get_extractor(u_int8 level, u_int32 type);

/*******************************************/

/*
 * decode the stream 
 */
int decode_stream(struct stream_object *so)
{
   struct po_list *pl;
   FUNC_EXTRACTOR_PTR(app_extractor);
   int ret = 0;

   /* get the port used by the stream, looking at the first packet */
   pl = TAILQ_FIRST(&so->po_head);
   
   /* 
    * we should run the extractor on both the tcp/udp ports
    * since we may be interested in both client and server traffic.
    */
   switch (pl->po.L4.proto) {
      case NL_TYPE_TCP:
         app_extractor = get_extractor(APP_LAYER_TCP, ntohs(pl->po.L4.src));
         EXECUTE_EXTRACTOR(app_extractor, so, ret);
         app_extractor = get_extractor(APP_LAYER_TCP, ntohs(pl->po.L4.dst));
         EXECUTE_EXTRACTOR(app_extractor, so, ret);
         break;
         
      case NL_TYPE_UDP:
         app_extractor = get_extractor(APP_LAYER_UDP, ntohs(pl->po.L4.src));
         EXECUTE_EXTRACTOR(app_extractor, so, ret);
         app_extractor = get_extractor(APP_LAYER_UDP, ntohs(pl->po.L4.dst));
         EXECUTE_EXTRACTOR(app_extractor, so, ret);
         break;
   }
   
   /* if at least one extractor has found something ret is positive */
   return ret;
}


/*
 * add a extractor to the extractors table 
 */
void add_extractor(u_int8 level, u_int32 type, FUNC_EXTRACTOR_PTR(extractor))
{
   struct dec_entry *e;

   SAFE_CALLOC(e, 1, sizeof(struct dec_entry));
   
   e->level = level;
   e->type = type;
   e->extractor = extractor;

   SLIST_INSERT_HEAD(&extractor_table, e, next); 

   return;
}


/*
 * get a extractor from the extractors table 
 */
void * get_extractor(u_int8 level, u_int32 type)
{
   struct dec_entry *e;
   void *ret;

   SLIST_FOREACH (e, &extractor_table, next) {
      if (e->level == level && e->type == type) {
         ret = (void *)e->extractor;
         return ret;
      }
   }

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

