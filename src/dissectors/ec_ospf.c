/*
    ettercap -- dissector ospf -- works over IP !

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

    $Id: ec_ospf.c,v 1.1 2003/09/29 10:00:41 alor Exp $
*/

/*
 *      0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |   Version #   |       5       |         Packet length         |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                          Router ID                            |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                           Area ID                             |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |           Checksum            |             AuType            |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                       Authentication                          |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |                       Authentication                          |
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
*/
 
#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>

#define OSPF_AUTH_LEN   8
#define OSPF_AUTH       1
#define OSPF_NO_AUTH    0

/* protos */

FUNC_DECODER(dissector_ospf);
void ospf_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init ospf_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_OSPF, dissector_ospf);
}

/* 
 * the passwords collected by ospf will not be logged
 * in logfile since it is not over TCP or UDP.
 * anyway we can print them in the user message window
 */

FUNC_DECODER(dissector_ospf)
{
   DECLARE_DISP_PTR_END(ptr, end);
   char tmp[MAX_ASCII_ADDR_LEN];
   char pass[12];

   /* don't complain about unused var */
   (void)end;
   
   /* skip empty packets */
   if (PACKET->DATA.len == 0)
      return NULL;

   DEBUG_MSG("OSPF --> dissector_ospf");
  
   /* authentication */
   if ( ptohs(ptr + 14) == OSPF_AUTH ) {
      
      DEBUG_MSG("\tDissector_ospf PASS");
      
      /* 
       * we use a local variable since this does 
       * not need to reach the top half
       */
      strncpy(pass, ptr + 16, OSPF_AUTH_LEN);
      
   } 

   /* no authentication */
   if ( ptohs(ptr + 14) == OSPF_NO_AUTH ) {
      
      DEBUG_MSG("\tDissector_ospf NO AUTH");
      
      strcpy(pass, "No Auth");
   }
   /* switch on the version */
   
   USER_MSG("ospf : %s:%d -> AUTH: %s \n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                             ntohs(PACKET->L4.dst), 
                                             pass);

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

