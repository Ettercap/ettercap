/*
    ettercap -- send the the wire functions

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_send.c,v 1.2 2003/03/08 16:30:49 alor Exp $
*/

#include <ec.h>
#include <ec_packet.h>

#include <pcap.h>
#include <libnet.h>

void send_init(void);
void send_close(void);
int send_to_L3(struct packet_object *po);
int send_to_L2(struct packet_object *po);
int send_to_bridge(struct packet_object *po);

static void hack_pcap_lnet(pcap_t *p, libnet_t *l);
/*******************************************/

/*
 * set up the lnet struct to have a socket to send packets
 */

void send_init(void)
{
   libnet_t *l;
   libnet_t *l3;
   libnet_t *lb;
   char lnet_errbuf[LIBNET_ERRBUF_SIZE];
   
   DEBUG_MSG("send_init %s", GBL_OPTIONS->iface);
   
   /* open the socket at layer 3 */
   l3 = libnet_init(LIBNET_RAW4_ADV, GBL_OPTIONS->iface, lnet_errbuf);               
   ON_ERROR(l3, NULL, "libnet_init() failed: %s", lnet_errbuf);
   
   /* open the socket at layer 2 */
   l = libnet_init(LIBNET_LINK_ADV, GBL_OPTIONS->iface, lnet_errbuf);               
   ON_ERROR(l, NULL, "libnet_init() failed: %s", lnet_errbuf);
   
   if (GBL_SNIFF->type == SM_BRIDGED) {
      /* open the socket on the other iface for bridging */
      lb = libnet_init(LIBNET_LINK_ADV, GBL_OPTIONS->iface_bridge, lnet_errbuf);               
      ON_ERROR(lb, NULL, "libnet_init() failed: %s", lnet_errbuf);
      GBL_LNET->lnet_bridge = lb;
      /* use the same socket for lnet and pcap */
      hack_pcap_lnet(GBL_PCAP->pcap_bridge, GBL_LNET->lnet_bridge);
   }
   
   GBL_LNET->lnet_L3 = l3;               
   GBL_LNET->lnet = l;               
      
   /* use the same socket for lnet and pcap */
   hack_pcap_lnet(GBL_PCAP->pcap, GBL_LNET->lnet);
 
   atexit(send_close);
   
}


void send_close(void)
{
   libnet_destroy(GBL_LNET->lnet);
   libnet_destroy(GBL_LNET->lnet_L3);

   if (GBL_SNIFF->type == SM_BRIDGED) 
      libnet_destroy(GBL_LNET->lnet_bridge);
   
   DEBUG_MSG("send_closed");
}

/*
 * send the packet at layer 3
 * the eth header will be handled by the kernel
 */

int send_to_L3(struct packet_object *po)
{
   static libnet_ptag_t t;
   int c;

   t = libnet_build_data( po->fwd_packet, po->fwd_len, GBL_LNET->lnet_L3, t);
   ON_ERROR(t, -1, "libnet_build_data");
   
   c = libnet_write(GBL_LNET->lnet_L3);
   ON_ERROR(c, -1, "libnet_write %d (%d)", po->fwd_len, c);
   
   return c;
}

/*
 * send the packet at layer 2
 * this can be used to send ARP messages
 */

int send_to_L2(struct packet_object *po)
{
   static libnet_ptag_t t;
   int c;
   
   t = libnet_build_data( po->packet, po->len, GBL_LNET->lnet, t);
   ON_ERROR(t, -1, "libnet_build_data");
   
   c = libnet_write(GBL_LNET->lnet);
   ON_ERROR(c, -1, "libnet_write %d (%d)", po->len, c);
   
   return c;
}

/*
 * send the packet to the bridge
 */

int send_to_bridge(struct packet_object *po)
{
   static libnet_ptag_t t;
   int c;
 
   /* XXX -- debug purpose */
   memcpy(po->packet, "AAAA", 4);
   
   t = libnet_build_data( po->packet, po->len, GBL_LNET->lnet_bridge, t);
   ON_ERROR(t, -1, "libnet_build_data");
   
   c = libnet_write(GBL_LNET->lnet_bridge);
   ON_ERROR(c, -1, "libnet_write %d (%d)", po->len, c);
   
   return c;
}


/*
 * a dirty hack to use the same socket for pcap and libnet.
 * both the structures contains a "int fd" field representing the socket.
 * we can close the fd opened by libnet and use the one already in use by pcap.
 * in this way we will not sniff packets sent by us at link layer.
 * expecially usefull in bridged sniffing.
 */

static void hack_pcap_lnet(pcap_t *p, libnet_t *l)
{
   DEBUG_MSG("hack_pcap_lnet (before) pcap %d | lnet %d", pcap_fileno(p), l->fd);
   
   /* close the lnet socket */
   close(l->fd);

   /* use the socket opened by pcap */
   l->fd = pcap_fileno(p);
   
   DEBUG_MSG("hack_pcap_lnet  (after) pcap %d | lnet %d", pcap_fileno(p), l->fd);
}


/* EOF */

// vim:ts=3:expandtab

