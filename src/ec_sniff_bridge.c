/*
    ettercap -- bridged sniffing method module

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

    $Id: ec_sniff_bridge.c,v 1.9 2003/12/13 18:41:11 alor Exp $
*/

#include <ec.h>
#include <ec_capture.h>
#include <ec_send.h>
#include <ec_threads.h>
#include <ec_conntrack.h>

/* proto */
void start_bridge_sniff(void);
void stop_bridge_sniff(void);
void forward_bridge_sniff(struct packet_object *po);

/*******************************************/

void start_bridge_sniff(void)
{
   DEBUG_MSG("start_bridge_sniff");
   
   /* create the timeouter thread */
   if (!GBL_OPTIONS->read)
      ec_thread_new("timer", "conntrack timeouter", &conntrack_timeouter, NULL);

   /* create the thread for packet capture */
   ec_thread_new("capture", "pcap handler and packet decoder", &capture, NULL);
   
   /* create the thread for packet capture on the bridged interface */
   ec_thread_new("bridge", "pcap handler and packet decoder", &capture_bridge, NULL);
   
   USER_MSG("Bridger sniffing was started...\n");
}

/*
 * kill the capturing threads, but leave untouched the others
 */
void stop_bridge_sniff(void)
{
   pthread_t pid;
   
   DEBUG_MSG("stop_bridge_sniff");
  
   /* get the pid and kill it */
   if ((pid = ec_thread_getpid("capture")) != 0)
      ec_thread_destroy(pid);
   
   if ((pid = ec_thread_getpid("bridge")) != 0)
      ec_thread_destroy(pid);

}


void forward_bridge_sniff(struct packet_object *po)
{
   /* don't forward dropped packets */
   if (po->flags & PO_DROPPED)
      return;
         
   /* 
    * send the packet to the other interface.
    * the socket was opened during the initialization
    * phase (parameters parsing) by bridge_init()
    */

   if (po->flags & PO_FROMIFACE)
      send_to_bridge(po);
   else if (po->flags & PO_FROMBRIDGE)
      send_to_L2(po);
   
}


/* EOF */

// vim:ts=3:expandtab

