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

    $Id: ec_sniff_unified.c,v 1.8 2003/09/18 22:15:03 alor Exp $
*/

#include <ec.h>
#include <ec_capture.h>
#include <ec_send.h>
#include <ec_threads.h>
#include <ec_inject.h>

/* proto */
void start_unified_sniff(void);
void forward_unified_sniff(struct packet_object *po);

/*******************************************/

void start_unified_sniff(void)
{
   DEBUG_MSG("start_unified_sniff");

   /* create the thread for packet capture */
   ec_thread_new("capture", "pcap handler and packet decoder", &capture, GBL_OPTIONS->iface);
}


void forward_unified_sniff(struct packet_object *po)
{
   /* if it was not initialized, no packet are forwardable */
   if (!GBL_LNET->lnet)
      return;

   /* if unoffensive is set, don't forward any packet */
   if (GBL_OPTIONS->unoffensive)
      return;

   /* don't forward dropped packets */
   if (po->flags & PO_DROPPED)
      return;
      
   /* 
    * forward the packet to Layer 3, the kernel
    * will route them to the correct destination (host or gw)
    */
    send_to_L3(po);

    /* 
     * if the packet was modified and it exceeded the mtu,
     * we have to inject the exceeded data
     */
    if (po->inject) {
       inject_po(po->inject);
       /* free the inject packet chain */
       inject_chain_free(po);
    }
}

/* EOF */

// vim:ts=3:expandtab

