/*
    ettercap -- bridged sniffing method module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_sniff_bridge.c,v 1.2 2003/03/13 13:22:07 alor Exp $
*/

#include <ec.h>
#include <ec_capture.h>
#include <ec_send.h>
#include <ec_threads.h>

/* proto */
void start_bridge_sniff(void);
void forward_bridge_sniff(struct packet_object *po);

/*******************************************/

void start_bridge_sniff(void)
{
   DEBUG_MSG("start_bridge_sniff");

   /* create the thread for packet capture */
   ec_thread_new("capture", "pcap handler and packet decoder", &capture, NULL);
   
   /* create the thread for packet capture on the bridged interface */
   ec_thread_new("bridge", "pcap handler and packet decoder", &capture_bridge, NULL);
}


void forward_bridge_sniff(struct packet_object *po)
{
   /* 
    * send the packet to the other interface.
    * the socket was opened during the initialization
    * phase (parameters parsing) by bridge_init()
    */

   /* XXX - implement the forwarding in two ways !! */
   
   //send_to_bridge(po);
   //send_to_L2(po);
}


/* EOF */

// vim:ts=3:expandtab

