/*
    ettercap -- passive information handling module

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

    $Id: ec_passive.c,v 1.6 2003/07/04 21:51:38 alor Exp $
*/

#include <ec.h>
#include <ec_passive.h>
#include <ec_decode.h>
#include <ec_packet.h>

/* globals */

/* protos */

int is_open_port(u_int8 proto, u_int16 port, u_int8 flags);

/************************************************/
  
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

int is_open_port(u_int8 proto, u_int16 port, u_int8 flags)
{

   switch (proto) {
      case NL_TYPE_TCP:
#if 0 
         /* detect priviledged port */
         if (ntohs(po->L4.src) > 0 && ntohs(po->L4.src) < 1024 )
            return 1;
#endif
         /* SYN+ACK packet are coming from open ports */
         if ( (flags & TH_SYN) && (flags & TH_ACK) )
            return 1;
         /* look in the table */
         if ( get_decoder(APP_LAYER_TCP, ntohs(port)) != NULL)
            return 1;
         break;
      case NL_TYPE_UDP:
         /* 
          * we cannot determine if the port is open or not...
          * suppose that all priveledged port used are open.
          */
         if (ntohs(port) > 0 && ntohs(port) < 1024 )
            return 1;
         /* look up in the table */
         if ( get_decoder(APP_LAYER_UDP, ntohs(port)) != NULL)
            return 1;
         break;
   }

   return 0;
}


/* EOF */

// vim:ts=3:expandtab

