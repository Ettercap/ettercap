/*
    etterlog -- create, search and manipulate streams

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

    $Id: el_stream.c,v 1.2 2004/09/24 15:10:02 alor Exp $
*/


#include <el.h>
#include <el_functions.h>

/* protos... */

void stream_init(struct stream_object *so);
int stream_add(struct stream_object *so, struct log_header_packet *pck, char *buf);
int stream_search(struct stream_object *so, char *buf, int versus);
int stream_read(struct stream_object *so, char *buf, size_t size, int mode);
void stream_move(struct stream_object *so, int offset, int whence);
   
/*******************************************/

/*
 * initialize a stream object
 */
void stream_init(struct stream_object *so)
{
   TAILQ_INIT(&so->po_head);
   so->po_off = 0;
   so->po_curr = NULL;
}

/*
 * add a packet to a stream
 */
int stream_add(struct stream_object *so, struct log_header_packet *pck, char *buf)
{
   struct po_list *pl, *tmp;

   /* skip ack packet or zero lenght packet */
   if (pck->len == 0)
      return 0;

   /* the packet is good, add it */
   SAFE_CALLOC(pl, 1, sizeof(struct po_list));

   /* create the packet object */
   memcpy(&pl->po.L3.src, &pck->L3_src, sizeof(struct ip_addr));
   memcpy(&pl->po.L3.dst, &pck->L3_dst, sizeof(struct ip_addr));
   
   pl->po.L4.src = pck->L4_src;
   pl->po.L4.dst = pck->L4_dst;
   pl->po.L4.proto = pck->L4_proto;
  
   SAFE_CALLOC(pl->po.DATA.data, pck->len, sizeof(char));
   
   memcpy(pl->po.DATA.data, buf, pck->len);
   pl->po.DATA.len = pck->len;
   
   /* set the stream direction */

   /* this is the first packet in the stream */
   if (TAILQ_FIRST(&so->po_head) == TAILQ_END(&so->po_head)) {
      pl->type = STREAM_SIDE1;
   /* check the previous one and set it accordingly */
   } else {
      tmp = TAILQ_LAST(&so->po_head, po_list_head);
      if (!ip_addr_cmp(&tmp->po.L3.src, &pl->po.L3.src))
         /* same direction */
         pl->type = tmp->type;
      else 
         /* change detected */
         pl->type = (tmp->type == STREAM_SIDE1) ? STREAM_SIDE2 : STREAM_SIDE1;
   }
      
   /* add to the queue */
   TAILQ_INSERT_TAIL(&so->po_head, pl, next);
   
   return pck->len;
}

int stream_search(struct stream_object *so, char *buf, int versus)
{
   return 0;
}

int stream_read(struct stream_object *so, char *buf, size_t size, int mode)
{
   return 0;
}

void stream_move(struct stream_object *so, int offset, int whence)
{
}


/* EOF */


// vim:ts=3:expandtab

