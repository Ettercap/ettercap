/*
    ettercap -- passive information handling module

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

    $Id: ec_passive.c,v 1.2 2003/04/05 09:25:09 alor Exp $
*/

#include <ec.h>
#include <ec_passive.h>
#include <ec_decode.h>
#include <ec_packet.h>

/* globals */

/* protos */

int is_open_port(struct packet_object *po);

/************************************************/
  
/*
 * return 1 if the port is to be considered open
 */

int is_open_port(struct packet_object *po)
{
   /*
    * the strategy for open port discovery is:
    *
    * if the port is less than 1024, it is open at high  probability
    * 
    * if it is a TCP packet, we can rely on the tcp flags.
    *    so syn+ack packet are coming from an open port.
    *
    * as a last resource, look in the registered dissector table.
    * if a port is registered, it might be opened.
    *
    */

   /* for both protocols */
   if (ntohs(po->L4.src) < 1024)
      return 1;
            
   switch (po->L4.proto) {
      case NL_TYPE_TCP:
         /* SYN+ACK packet are coming from open ports */
         if ( (po->L4.flags & TH_SYN) && (po->L4.flags & TH_ACK) )
            return 1;
         /* look in the table */
         if ( get_decoder(APP_LAYER_TCP, ntohs(po->L4.src)) != NULL)
            return 1;
         break;
      case NL_TYPE_UDP:
         /* look up in the table */
         if ( get_decoder(APP_LAYER_UDP, ntohs(po->L4.src)) != NULL)
            return 1;
         break;
   }

   return 0;
}


/* EOF */

// vim:ts=3:expandtab

