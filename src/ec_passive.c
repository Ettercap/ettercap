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

    $Id: ec_passive.c,v 1.1 2003/03/31 21:46:50 alor Exp $
*/

#include <ec.h>
#include <ec_passive.h>
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
    * it it is a SYN+ACK tcp packet, it is open.
    * it it is a port < 1024 udp, at high probability it is open
    * skip all the other ports (set them to zero)
    */

   switch (po->L4.proto) {
      case NL_TYPE_TCP:
         /* skip non SYN+ACK packet */
         if ( (po->L4.flags & TH_SYN) && (po->L4.flags & TH_ACK) )
            return 1;
         break;
      case NL_TYPE_UDP:
         /* skip port > 1024 */
         if (ntohs(po->L4.src) < 1024)
            return 1;
         break;
   }

   return 0;
}


/* EOF */

// vim:ts=3:expandtab

