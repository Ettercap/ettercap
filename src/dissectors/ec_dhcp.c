/*
    ettercap -- dissector DHCP -- UDP 67

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

    $Id: ec_dhcp.c,v 1.3 2003/10/17 16:19:30 alor Exp $
*/

/*
 * RFC: 2131
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     op (1)    |   htype (1)   |   hlen (1)    |   hops (1)    |
 *    +---------------+---------------+---------------+---------------+
 *    |                            xid (4)                            |
 *    +-------------------------------+-------------------------------+
 
 *    |           secs (2)            |           flags (2)           |
 *    +-------------------------------+-------------------------------+
 *    |                          ciaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          yiaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          siaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          giaddr  (4)                          |
 *    +---------------------------------------------------------------+
 *    |                          chaddr  (16)                         |
 *    +---------------------------------------------------------------+
 *    |                          sname   (64)                         |
 *    +---------------------------------------------------------------+
 *    |                          file    (128)                        |
 *    +---------------------------------------------------------------+
 *    |                       options  (variable)                     |
 *    +---------------------------------------------------------------+
 */


#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>

/* globalse */

struct dhcp_hdr {
   u_int8   op;
      #define BOOTREQUEST  1
      #define BOOTREPLY    2
   u_int8   htype;
   u_int8   hlen;
   u_int8   hops;
   u_int32  id;
   u_int16  secs;
   u_int16  flags;
   u_int32  ciaddr;
   u_int32  yiaddr;
   u_int32  siaddr;
   u_int32  giaddr;
   u_int8   chaddr[16];
   u_int8   sname[64];
   u_int8   file[128];
};

#define DHCP_DISCOVER      0x01
#define DHCP_OFFER         0x02
#define DHCP_REQUEST       0x03
#define DHCP_ACK           0x05

#define DHCP_MAGIC_COOKIE  "\x63\x82\x53\x63"
#define OPT_NETMASK        0x01
#define OPT_ROUTER         0x03
#define OPT_DNS            0x06
#define OPT_DOMAIN         0x0f
#define OPT_RQ_ADDR        0x32
#define OPT_LEASE_TIME     0x33
#define OPT_MSG_TYPE       0x35
#define OPT_SRV_ADDR       0x36
#define OPT_RENEW_TIME     0x3a
#define OPT_CLI_IDENT      0x3d
#define OPT_END            0xff

/* protos */

FUNC_DECODER(dissector_dhcp);
void dhcp_init(void);
static u_int8 * get_option(u_int8 opt, u_int8 *ptr, u_int8 *end);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init dhcp_init(void)
{
   dissect_add("dhcp", APP_LAYER_UDP, 67, dissector_dhcp);
}


FUNC_DECODER(dissector_dhcp)
{
   DECLARE_DISP_PTR_END(ptr, end);
   char tmp[MAX_ASCII_ADDR_LEN];
   struct dhcp_hdr *dhcp;
   u_int8 *options, *opt;

   (void)end;
   
   /* sanity check */
   if (PACKET->DATA.len < sizeof(struct dhcp_hdr))
      return NULL;
         
   DEBUG_MSG("DHCP --> UDP 68  dissector_dhcp");

   /* cast the header and options */
   dhcp = (struct dhcp_hdr *)ptr;
   options = (u_int8 *)(dhcp + 1);

   /* check for the magic cookie */
   if (memcmp(options, DHCP_MAGIC_COOKIE, 4))
      return NULL;

   /* move to the first option */
   options += 4;
   
   /* search the "message type" option */
   opt = get_option(OPT_MSG_TYPE, options, end);

   /* option not found */
   if (opt == NULL)
      return NULL;
      
   /* client requests */ 
   if (FROM_CLIENT("dhcp", PACKET)) {
      struct ip_addr client;
      
      /* clients only send request */
      if (dhcp->op != BOOTREQUEST)
         return NULL;
      
      switch (*(opt + 1)) {
         case DHCP_DISCOVER:
            DEBUG_MSG("\tDissector_DHCP DISCOVER");
            
            USER_MSG("DHCP: [%s] DISCOVER \n", mac_addr_ntoa(dhcp->chaddr, tmp)); 
            
            break;
            
         case DHCP_REQUEST:
            DEBUG_MSG("\tDissector_DHCP REQUEST");
      
            /* netmask */
            if ((opt = get_option(OPT_RQ_ADDR, options, end)) != NULL)
               ip_addr_init(&client, AF_INET, opt + 1);
            
            USER_MSG("DHCP: [%s] REQUEST ", mac_addr_ntoa(dhcp->chaddr, tmp)); 
            USER_MSG("%s\n", ip_addr_ntoa(&client, tmp)); 
      
            break;
      }

      /* HOOK POINT: HOOK_PROTO_DHCP */
      hook_point(HOOK_PROTO_DHCP, PACKET);
      
         
   /* server replies */ 
   } else {
      struct ip_addr netmask;
      struct ip_addr router;
      struct ip_addr client;
      struct ip_addr dns;
      char domain[64];
      
      /* servers only send replies */
      if (dhcp->op != BOOTREPLY)
         return NULL;

      switch (*(opt + 1)) {
         case DHCP_ACK:
            DEBUG_MSG("\tDissector_DHCP ACK");
   
            /* get the assigned ip */
            ip_addr_init(&client, AF_INET, (char *)&dhcp->yiaddr );
            
            /* netmask */
            if ((opt = get_option(OPT_NETMASK, options, end)) != NULL)
               ip_addr_init(&netmask, AF_INET, opt + 1);
            
            /* default gateway */
            if ((opt = get_option(OPT_ROUTER, options, end)) != NULL)
               ip_addr_init(&router, AF_INET, opt + 1);
            
            /* dns server */
            if ((opt = get_option(OPT_DNS, options, end)) != NULL)
               ip_addr_init(&dns, AF_INET, opt + 1);
            
            USER_MSG("DHCP: [%s] ACK : ", ip_addr_ntoa(&PACKET->L3.src, tmp)); 
            USER_MSG("%s ", ip_addr_ntoa(&client, tmp)); 
            USER_MSG("%s ", ip_addr_ntoa(&netmask, tmp)); 
            USER_MSG("GW %s ", ip_addr_ntoa(&router, tmp)); 
            USER_MSG("DNS %s ", ip_addr_ntoa(&dns, tmp)); 
            
            /* dns domain */
            if ((opt = get_option(OPT_DOMAIN, options, end)) != NULL) {
                  strncpy(domain, opt + 1, MIN(*opt, sizeof(domain)) );
            
               USER_MSG("\"%s\"\n", domain);
            } else
               USER_MSG("\n");
            
            break;
            
      }
   }
      
   return NULL;
}


/*
 * return the pointer to the named option
 * or NULL if not found
 * ptr will point to the length of the option
 */
static u_int8 * get_option(u_int8 opt, u_int8 *ptr, u_int8 *end)
{
   do {

      /* we have found our option */
      if (*ptr == opt)
         return ptr + 1;

      /* 
       * move thru options :
       *
       * OPT LEN .. .. .. OPT LEN .. ..
       */
      ptr = ptr + 2 + (*(ptr + 1));

   } while (*ptr != OPT_END && ptr < end);
   
   return NULL;
}

/* EOF */

// vim:ts=3:expandtab

