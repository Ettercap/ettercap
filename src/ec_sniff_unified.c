/*
    ettercap -- unified sniffing method module

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

    $Id: ec_sniff_unified.c,v 1.14 2003/12/13 18:41:11 alor Exp $
*/

#include <ec.h>
#include <ec_capture.h>
#include <ec_send.h>
#include <ec_threads.h>
#include <ec_inject.h>
#include <ec_conntrack.h>

/* proto */
void start_unified_sniff(void);
void stop_unified_sniff(void);
void forward_unified_sniff(struct packet_object *po);

/*******************************************/

/*
 * creates the threads for capturing 
 */
void start_unified_sniff(void)
{
   DEBUG_MSG("start_unified_sniff");
   
   /* create the timeouter thread */
   if (!GBL_OPTIONS->read && ec_thread_getpid("timer") == 0)
      ec_thread_new("timer", "conntrack timeouter", &conntrack_timeouter, NULL);

   /* create the thread for packet capture */
   ec_thread_new("capture", "pcap handler and packet decoder", &capture, GBL_OPTIONS->iface);

   USER_MSG("Unified sniffing was started...\n");
}


/*
 * kill the capturing threads, but leave untouched the others
 */
void stop_unified_sniff(void)
{
   pthread_t pid;
   
   DEBUG_MSG("stop_unified_sniff");
  
   /* get the pid and kill it */
   if ((pid = ec_thread_getpid("capture")) != 0)
      ec_thread_destroy(pid);

}


void forward_unified_sniff(struct packet_object *po)
{
   /* if it was not initialized, no packet are forwardable */
   if (!GBL_LNET->lnet)
      return;

   /* if unoffensive is set, don't forward any packet */
   if (GBL_OPTIONS->unoffensive)
      return;

   /* 
    * forward the packet to Layer 3, the kernel
    * will route them to the correct destination (host or gw)
    */

   /* don't forward dropped packets */
   if ((po->flags & PO_DROPPED) == 0)
      send_to_L3(po);

    /* 
     * if the packet was modified and it exceeded the mtu,
     * we have to inject the exceeded data
     */
    if (po->DATA.inject) 
       inject_buffer(po); 
}

/* EOF */

// vim:ts=3:expandtab

