/*
    ettercap -- dissector BGP 4 -- TCP 179

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

    $Id: ec_bgp.c,v 1.1 2003/09/22 12:30:42 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>


/* protos */

FUNC_DECODER(dissector_bgp);
void bgp_init(void);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init bgp_init(void)
{
   dissect_add("bgp", APP_LAYER_TCP, 179, dissector_bgp);
}

FUNC_DECODER(dissector_bgp)
{
   DECLARE_DISP_PTR_END(ptr, end);
   char tmp[MAX_ASCII_ADDR_LEN];
   u_char *parameters;
   u_char param_length;
   u_int16 i;
   u_char BGP_MARKER[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                          0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

   /* skip empty packets (ACK packets) */
   if (PACKET->DATA.len == 0)
      return NULL;

   /* not the right version (4) */
   if ( ptr[19] != 4 ) 
      return 0;                  
   
   /* not a OPEN message */
   if ( ptr[18] != 1 ) 
      return 0;
                     
   /* BGP marker has to be FFFFFF... */
   if ( memcmp(ptr, BGP_MARKER, 16) ) 
      return 0;
   
   /* no optional parameter */
   if ( (param_length = ptr[28]) == 0 ) 
      return 0; 

   /* skip to parameters */
   parameters = ptr + 29;

   DEBUG_MSG("\tDissector_BGP");

   /* move through the param list */
   for ( i = 0; i <= param_length; i += (parameters[i+1]+2) ) {

      /* the parameter is an authentication type (1) */
      if (parameters[i] == 1) {
         u_char j, *str_ptr;
         u_char len = parameters[i+1];
        
         DEBUG_MSG("\tDissector_BGP 4 AUTH");
         
         PACKET->DISSECTOR.user = strdup("");
         PACKET->DISSECTOR.pass = calloc(len*3+10 ,1);
         PACKET->DISSECTOR.info = calloc(32,1);

         /* Get authentication type */
         sprintf(PACKET->DISSECTOR.info, "AUTH TYPE [0x%02x]", parameters[i+2]);
         
         /* Get authentication data */
         if (len > 1) {
            sprintf(PACKET->DISSECTOR.pass,"Hex(");
            str_ptr = PACKET->DISSECTOR.pass + strlen(PACKET->DISSECTOR.pass);
            
            for (j = 0; j < (len-1); j++)
               sprintf(str_ptr + (j * 3), " %.2x", parameters[i+3+j]);
         
            strcat(str_ptr, " )");
         }	 
         
         USER_MSG("bgp : %s:%d -> %s  %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                             ntohs(PACKET->L4.dst), 
                                             PACKET->DISSECTOR.info,
                                             PACKET->DISSECTOR.pass);
   
         return NULL;
      }
   }
   
   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

