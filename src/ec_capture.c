/*
    ettercap -- iface and capture functions

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_capture.c,v 1.5 2003/03/17 19:42:25 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_threads.h>
#include <ec_ui.h>

#include <sys/socket.h>

#include <pcap.h>

#ifdef OS_LINUX
#define PCAP_TIMEOUT 0
#else
/* BSD and Solaris sux */
#define PCAP_TIMEOUT 1
#endif

void capture_init(void);
void capture_close(void);
EC_THREAD_FUNC(capture);
EC_THREAD_FUNC(capture_bridge);

/*******************************************/

/*
 * set up the pcap to capture from the specified interface
 * set up even the first dissector by looking at DLT_*
 */

void capture_init(void)
{
   pcap_t *pd;
   pcap_t *pb = NULL; /* for the bridge */
   pcap_dumper_t *pdump;
   int dlt;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   
   /*
    * if the user didn't specified the interface,
    * we have to found one...
    */
   
   if (GBL_OPTIONS->iface == NULL) {
      char *ifa = pcap_lookupdev(pcap_errbuf);
      ON_ERROR(ifa, NULL, "No suitable interface found...");
      
      GBL_OPTIONS->iface = strdup(ifa);
   }
   
   DEBUG_MSG("capture_init %s", GBL_OPTIONS->iface);
              
   if (GBL_SNIFF->type == SM_BRIDGED) {
      if (!strcmp(GBL_OPTIONS->iface, GBL_OPTIONS->iface_bridge))
         FATAL_MSG("Bridging iface must be different from %s", GBL_OPTIONS->iface);
      USER_MSG("Bridging %s and %s...\n\n", GBL_OPTIONS->iface, GBL_OPTIONS->iface_bridge);
   } else
      USER_MSG("Listening on %s...\n\n", GBL_OPTIONS->iface);
   
   /*
    * set the snaplen to maximum
    */
   
   GBL_PCAP->snaplen = 9999;
   
   /* 
    * open the interface from GBL_OPTIONS (user specified)
    */

   if (GBL_OPTIONS->read)
      pd = pcap_open_offline(GBL_OPTIONS->dumpfile, pcap_errbuf);
   else
      pd = pcap_open_live(GBL_OPTIONS->iface, GBL_PCAP->snaplen, GBL_PCAP->promisc, 
                   PCAP_TIMEOUT, pcap_errbuf);
   
   ON_ERROR(pd, NULL, "%s", pcap_errbuf);

   /* if in bridged sniffing, we have to open even the other iface */
   if (GBL_SNIFF->type == SM_BRIDGED) {
      pb = pcap_open_live(GBL_OPTIONS->iface_bridge, GBL_PCAP->snaplen, GBL_PCAP->promisc, 
                   PCAP_TIMEOUT, pcap_errbuf);
   
      ON_ERROR(pb, NULL, "%s", pcap_errbuf);
   }

   if (GBL_OPTIONS->dump) {
      pdump = pcap_dump_open(pd, GBL_OPTIONS->dumpfile);
      GBL_PCAP->dump = pdump;               
   }
   
   /*
    * set the right decoder for L2
    */
   
   dlt = pcap_datalink(pd);
   
   /* check that the bridge type is the same as the main iface */
   if (GBL_SNIFF->type == SM_BRIDGED && pcap_datalink(pb) != dlt)
      FATAL_MSG("You can NOT bridge two different type of interfaces !");
   
   if (set_L2_decoder(dlt) != ESUCCESS) {
      if (GBL_OPTIONS->read)
         FATAL_MSG("Dump file not supported (DLT = %d)", dlt);
      else
         FATAL_MSG("Inteface %s not supported (DLT = %d)", GBL_OPTIONS->iface, dlt);
   }
  
   GBL_PCAP->dlt = dlt;
   
   /* set the global descriptor for both the iface and the bridge */
   
   GBL_PCAP->pcap = pd;               
   if (GBL_SNIFF->type == SM_BRIDGED)
      GBL_PCAP->pcap_bridge = pb;
 
   /* on exit clean up the structures */
   atexit(capture_close);
   
}


void capture_close(void)
{
   pcap_close(GBL_PCAP->pcap);
   if (GBL_OPTIONS->dump)
      pcap_dump_close(GBL_PCAP->dump);
   
   if (GBL_SNIFF->type == SM_BRIDGED)
      pcap_close(GBL_PCAP->pcap_bridge);
   
   DEBUG_MSG("ATEXIT: capture_closed");
}

/*
 * start capturing packets
 */

EC_THREAD_FUNC(capture)
{
   DEBUG_MSG("neverending loop (capture)");
  
   ec_thread_init();
   
   /* 
    * infinite loop 
    * dispatch packets to ec_decode
    */

   pcap_loop(GBL_PCAP->pcap, -1, ec_decode, EC_THREAD_PARAM);

   return NULL;
}


EC_THREAD_FUNC(capture_bridge)
{
   DEBUG_MSG("neverending loop (capture_bridge)");
  
   ec_thread_init();
   
   /* 
    * infinite loop 
    * dispatch packets to ec_decode
    */
        
   pcap_loop(GBL_PCAP->pcap_bridge, -1, ec_decode, EC_THREAD_PARAM);

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

