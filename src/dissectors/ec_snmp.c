/*
    ettercap -- dissector snmp -- UDP 161

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

    $Id: ec_snmp.c,v 1.1 2003/07/17 21:13:12 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>

#define ASN1_INTEGER    2                                                                           
#define ASN1_STRING     4                                                                           
#define ASN1_SEQUENCE   16 

#define SNMP_VERSION_1  0
#define SNMP_VERSION_2c 1
#define SNMP_VERSION_2u 2
#define SNMP_VERSION_3  3

/* protos */

FUNC_DECODER(dissector_snmp);
void snmp_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init snmp_init(void)
{
   dissect_add("snmp", APP_LAYER_UDP, 161, dissector_snmp);
}

FUNC_DECODER(dissector_snmp)
{
   DECLARE_DISP_PTR_END(ptr, end);
   size_t clen = 0;
   char tmp[MAX_ASCII_ADDR_LEN];
   int version, n;

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;
   
   DEBUG_MSG("SNMP --> UDP dissector_snmp");

   /* get the version */
   while (*ptr++ != ASN1_INTEGER && ptr != end);
      
   /* move to the len */
   ptr += *ptr;

   /* get the version */
   version = *ptr++;

   /* convert the version to real number */
   if (version++ > 3)
      version = 3;
   
   /* move till the community name len */
   while(*ptr++ != ASN1_STRING && ptr != end);

   /* get the community name lenght */
   n = *ptr;
   
   if (n >= 128) {
      n &= ~128;
      ptr += n;
      
      switch(*ptr) {
         case 1:
            clen = *ptr;
            break;
         case 2:
            clen = *(u_int16 *)ptr;
            break;
         case 3:
            ptr--;
            clen = *(u_int32 *)ptr++;
            clen &= 0xfff;
            break;
         case 4:
            clen = *(u_int32 *)ptr;
            break;
      }
   } else
      clen = *ptr;

   /* update the pointer */
   ptr++;
   

   PACKET->DISSECTOR.user = calloc(clen + 2, sizeof(char));
   ON_ERROR(PACKET->DISSECTOR.user, NULL, "Can't allocate memory");

   /* fill the structure */
   snprintf(PACKET->DISSECTOR.user, clen + 1, "%s", ptr);
   PACKET->DISSECTOR.pass = strdup("");
   PACKET->DISSECTOR.info = strdup("SNMP v ");
   /* put the number in the string */
   PACKET->DISSECTOR.info[6] = version + 48;
   
   USER_MSG("SNMP : %s:%d -> USER: %s  PASS: %s  INFO: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                 ntohs(PACKET->L4.dst), 
                                 PACKET->DISSECTOR.user,
                                 PACKET->DISSECTOR.pass,
                                 PACKET->DISSECTOR.info);
   

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

