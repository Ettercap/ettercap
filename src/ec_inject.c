/*
    ettercap -- TCP/UDP injection module

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

    $Id: ec_inject.c,v 1.3 2003/09/27 09:53:33 alor Exp $
*/

#include <ec.h>
#include <ec_packet.h>

/* proto */

int inject_buffer(struct packet_object *po, u_int8 buf, size_t len);
int inject_po(struct packet_object *po);

/*******************************************/

/*
 * the idea is that the application will pass a buffer
 * and a len, and this function will split up the 
 * buffer to fit the MTU and create an inject chain.
 * then it will inject the chain.
 */
int inject_buffer(struct packet_object *po, u_int8 buf, size_t len)
{

   /* the packet_object passed is a fake.
    * it is used only to pass:
    *    - IP source and dest
    *    - IPPROTO
    *    - (tcp/udp) port source and dest
    * all the field have to be filled int and the buffer
    * has to be alloc'd
    */
   
#if 0
   alloc the buffer for the first MTU-(L3.len+L4.len) bytes

   len -= MTU-(L3.len+L4.len);
      
   if (po->L4.proto == NL_TYPE_TCP)
      get the session magic number from tcp
      
   prepare the L3 header in the po->buffer

   prepare the L4 header in the po->buffer (udp or tcp)

   make a consistent packet object 
   (the important fields are fwd_packet and fwd_len)

   if (len)
      make another packet linked with po->inject (recursion ?)

   /* sent the packet 
    *
    * PAY ATTENTION ON THE LOCK !!!
    * where do we have to lock ?
    */
   inject_po(po);
   
#endif
   
   return ESUCCESS;
}


/*
 * inject the packet and all its packet chain
 */
int inject_po(struct packet_object *po)
{

#if 0
   /* get the session magic numbers */
   get_tcp_session(...);
   
   adjust the sessions...
   
   /* send this packet */
   send_L3(po);
   
   /* inject the next packet in the chain */
   inject_po(po->inject);
  
   if (... errors... )
      return -ENOTHANDLED;
#endif

   return ESUCCESS;
}



/* EOF */

// vim:ts=3:expandtab

