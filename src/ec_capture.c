/*
    ettercap -- iface and capture functions

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_capture.c,v 1.19 2003/07/18 21:36:45 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_threads.h>
#include <ec_ui.h>

#include <sys/socket.h>
#include <sys/stat.h>

#include <pcap.h>
#include <libnet.h>

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

void get_hw_info(void);
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
   bpf_u_int32 net, mask;
   struct bpf_program bpf;
   int dlt;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
   
   /*
    * if the user didn't specified the interface,
    * we have to found one...
    */
   
   if (!GBL_OPTIONS->read && GBL_OPTIONS->iface == NULL) {
      char *ifa = pcap_lookupdev(pcap_errbuf);
      ON_ERROR(ifa, NULL, "No suitable interface found...");
      
      GBL_OPTIONS->iface = strdup(ifa);
   }
   
   DEBUG_MSG("capture_init %s", GBL_OPTIONS->iface);
              
   if (GBL_SNIFF->type == SM_BRIDGED) {
      if (!strcmp(GBL_OPTIONS->iface, GBL_OPTIONS->iface_bridge))
         FATAL_ERROR("Bridging iface must be different from %s", GBL_OPTIONS->iface);
      USER_MSG("Bridging %s and %s...\n\n", GBL_OPTIONS->iface, GBL_OPTIONS->iface_bridge);
   } else if (GBL_OPTIONS->read) {
      USER_MSG("Reading from %s...\n\n", GBL_OPTIONS->dumpfile);
   } else
      USER_MSG("Listening on %s...\n\n", GBL_OPTIONS->iface);
   
   /* set the snaplen to maximum */
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

   /* get the file size */
   if (GBL_OPTIONS->read) {
      struct stat st;
      fstat(fileno(pcap_file(pd)), &st);
      GBL_PCAP->dump_size = st.st_size;
   }

   /* set the pcap filters */
   if (GBL_PCAP->filter != NULL) {
   
      if (pcap_lookupnet(GBL_OPTIONS->iface, &net, &mask, pcap_errbuf) == -1)
         ERROR_MSG("%s", pcap_errbuf);

      if (pcap_compile(pd, &bpf, GBL_PCAP->filter, 1, mask) < 0)
         ERROR_MSG("%s", pcap_errbuf);
            
      if (pcap_setfilter(pd, &bpf) == -1)
         ERROR_MSG("pcap_setfilter");

      pcap_freecode(&bpf);
   }
   
   /* if in bridged sniffing, we have to open even the other iface */
   if (GBL_SNIFF->type == SM_BRIDGED) {
      pb = pcap_open_live(GBL_OPTIONS->iface_bridge, GBL_PCAP->snaplen, GBL_PCAP->promisc, 
                   PCAP_TIMEOUT, pcap_errbuf);
   
      ON_ERROR(pb, NULL, "%s", pcap_errbuf);
   
      /* set the pcap filters */
      if (GBL_PCAP->filter != NULL) {
   
         if (pcap_lookupnet(GBL_OPTIONS->iface_bridge, &net, &mask, pcap_errbuf) == -1)
            ERROR_MSG("%s", pcap_errbuf);

         if (pcap_compile(pb, &bpf, GBL_PCAP->filter, 1, mask) < 0)
            ERROR_MSG("%s", pcap_errbuf);
            
         if (pcap_setfilter(pb, &bpf) == -1)
            ERROR_MSG("pcap_setfilter");

         pcap_freecode(&bpf);
      }
   }


   /* open the dump file */
   if (GBL_OPTIONS->write) {
      pdump = pcap_dump_open(pd, GBL_OPTIONS->dumpfile);
      GBL_PCAP->dump = pdump;               
   }
   
   
   /* set the right decoder for L2 */
   dlt = pcap_datalink(pd);
   
   /* check that the bridge type is the same as the main iface */
   if (GBL_SNIFF->type == SM_BRIDGED && pcap_datalink(pb) != dlt)
      FATAL_ERROR("You can NOT bridge two different type of interfaces !");
   
   if (set_L2_decoder(dlt) != ESUCCESS) {
      if (GBL_OPTIONS->read)
         FATAL_ERROR("Dump file not supported (DLT = %d)", dlt);
      else
         FATAL_ERROR("Inteface \"%s\" not supported (DLT = %d)", GBL_OPTIONS->iface, dlt);
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
   if (GBL_OPTIONS->write)
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


/* 
 * retrieve the IP and the MAC address of the hardware
 * used to sniff (primary iface or bridge)
 */

void get_hw_info(void)
{
   u_long ip;
   struct libnet_ether_addr *ea;
   bpf_u_int32 network, netmask;
   char pcap_errbuf[PCAP_ERRBUF_SIZE];
 
   /* dont touch the interface reading from file */
   if (!GBL_LNET->lnet) {
      DEBUG_MSG("get_hw_info: skipping... (not initialized)");
      return;
   }
   
   DEBUG_MSG("get_hw_info");
   
   ip = libnet_get_ipaddr4(GBL_LNET->lnet);

   /* if ip is equal to -1 there was an error */
   if (ip != (u_long)~0) {
      ip_addr_init(&GBL_IFACE->ip, AF_INET, (char *)&ip);
      
      if (pcap_lookupnet(GBL_OPTIONS->iface, &network, &netmask, pcap_errbuf) == -1)
         ERROR_MSG("%s", pcap_errbuf);
      
      ip_addr_init(&GBL_IFACE->network, AF_INET, (char *)&network);

      /* the user has specified a different netmask, use it */
      if (GBL_OPTIONS->netmask) {
         struct in_addr net;
         /* sanity check */
         if (inet_aton(GBL_OPTIONS->netmask, &net) == 0)
            FATAL_ERROR("Invalid netmask %s", GBL_OPTIONS->netmask);

         ip_addr_init(&GBL_IFACE->netmask, AF_INET, (char *)&net);
      } else
         ip_addr_init(&GBL_IFACE->netmask, AF_INET, (char *)&netmask);
      
   } else
      DEBUG_MSG("NO IP on %s", GBL_OPTIONS->iface);
   
   ea = libnet_get_hwaddr(GBL_LNET->lnet);

   if (ea != NULL)
      memcpy(GBL_IFACE->mac, ea->ether_addr_octet, ETH_ADDR_LEN);
   else
      DEBUG_MSG("NO MAC for %s", GBL_OPTIONS->iface);


   USER_MSG("%6s ->\t%s  ",  GBL_OPTIONS->iface,
            mac_addr_ntoa(GBL_IFACE->mac, pcap_errbuf));
   USER_MSG("%16s  ", ip_addr_ntoa(&GBL_IFACE->ip, pcap_errbuf));
   USER_MSG("%16s\n\n", ip_addr_ntoa(&GBL_IFACE->netmask, pcap_errbuf) );
   
   /* if not in bridged sniffing, return */
   if (GBL_SNIFF->type != SM_BRIDGED)
      return;
   
   ip = libnet_get_ipaddr4(GBL_LNET->lnet_bridge);

   /* if ip is equal to -1 there was an error */
   if (ip != (u_long)~0) {
      ip_addr_init(&GBL_BRIDGE->ip, AF_INET, (char *)&ip);
      
      if (pcap_lookupnet(GBL_OPTIONS->iface_bridge, &network, &netmask, pcap_errbuf) == -1)
         ERROR_MSG("%s", pcap_errbuf);
      
      ip_addr_init(&GBL_BRIDGE->network, AF_INET, (char *)&network);
      ip_addr_init(&GBL_BRIDGE->netmask, AF_INET, (char *)&netmask);
      
   } else
      DEBUG_MSG("NO IP on %s", GBL_OPTIONS->iface_bridge);
   
   ea = libnet_get_hwaddr(GBL_LNET->lnet_bridge);

   if (ea != NULL)
      memcpy(GBL_BRIDGE->mac, ea->ether_addr_octet, ETH_ADDR_LEN);
   else
      DEBUG_MSG("NO MAC for %s", GBL_OPTIONS->iface);
   
   
   USER_MSG("%6s ->\t%s  ",  GBL_OPTIONS->iface_bridge,
            mac_addr_ntoa(GBL_BRIDGE->mac, pcap_errbuf));
   USER_MSG("%16s  ", ip_addr_ntoa(&GBL_BRIDGE->ip, pcap_errbuf));
   USER_MSG("%16s\n\n", ip_addr_ntoa(&GBL_BRIDGE->netmask, pcap_errbuf) );
}


/* EOF */

// vim:ts=3:expandtab

