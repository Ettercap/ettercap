/*
    ettercap -- 802.11b (wifi) decoder module

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

    $Id: ec_wifi.c,v 1.11 2004/05/08 10:17:10 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_capture.h>

/* globals */

struct wifi_header {
   u_int8   type;
      #define WIFI_DATA    0x08
      #define WIFI_BACON   0x80
      #define WIFI_ACK     0xd4
   u_int8   control;
      #define WIFI_EXITING  0x01
      #define WIFI_ENTERING 0x02
      #define WIFI_ADHOC    0x03
      #define WIFI_WEP      0x40
   u_int16  duration;
   u_int8   dha[ETH_ADDR_LEN];
   u_int8   sha[ETH_ADDR_LEN];
   u_int8   bssid[ETH_ADDR_LEN];
   u_int16  seq;
};

struct llc_header {
   u_int8   dsap;
   u_int8   ssap;
   u_int8   control;
   u_int8   org_code[3];
   u_int16  proto;
};

struct wep_header {
   u_int8   init_vector[3];
   u_int8   key;
};

/* encapsulated ethernet */
u_int8 WIFI_ORG_CODE[3] = {0x00, 0x00, 0x00};

/* protos */

FUNC_DECODER(decode_wifi);
FUNC_ALIGNER(align_wifi);
void wifi_init(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init wifi_init(void)
{
   add_decoder(LINK_LAYER, IL_TYPE_WIFI, decode_wifi);
   add_aligner(IL_TYPE_WIFI, align_wifi);
}


FUNC_DECODER(decode_wifi)
{
   struct wifi_header *wifi;
   struct llc_header *llc;
   FUNC_DECODER_PTR(next_decoder) = NULL;

   DECODED_LEN = sizeof(struct wifi_header);
      
   wifi = (struct wifi_header *)DECODE_DATA;
   
   /* we are interested only in wifi data packets */
   if (wifi->type != WIFI_DATA) {
      return NULL;
   }

   /* the frame is crypted with WEP */
   if (wifi->control & WIFI_WEP) {
      /* XXX add support for WEP */
      return NULL;
   }
   
   /* 
    * capture only "complete" and not retransitted packets 
    * we don't want to deal with fragments (0x04) or retransmission (0x08) 
    */
   if (wifi->control == WIFI_ENTERING || wifi->control == WIFI_EXITING) {
      /* get the logica link layer header */
      llc = (struct llc_header *)(wifi + 1);
      DECODED_LEN += sizeof(struct llc_header);
      
   } else if (wifi->control == WIFI_ADHOC) {
      /* 
       * get the logica link layer header i
       * there is one more field in adhoc mode
       */
      llc = (struct llc_header *)((u_char *)wifi + sizeof(struct wifi_header) + MEDIA_ADDR_LEN);
      DECODED_LEN += sizeof(struct llc_header) + MEDIA_ADDR_LEN;
      
   } else {
      return NULL;
   }
   
   /* org_code != encapsulated ethernet not yet supported */
   if (memcmp(llc->org_code, WIFI_ORG_CODE, 3))
      //return NULL;
      NOT_IMPLEMENTED();
      
   /* fill the bucket with sensitive data */
   PACKET->L2.header = (u_char *)DECODE_DATA;
   PACKET->L2.proto = IL_TYPE_WIFI;
   PACKET->L2.len = DECODED_LEN;
   
   memcpy(PACKET->L2.src, wifi->sha, ETH_ADDR_LEN);
   memcpy(PACKET->L2.dst, wifi->dha, ETH_ADDR_LEN);

   /* HOOK POINT: HOOK_PACKET_WIFI */
   hook_point(HOOK_PACKET_WIFI, po);
   
   /* leave the control to the next decoder */
   next_decoder = get_decoder(NET_LAYER, ntohs(llc->proto));
   EXECUTE_DECODER(next_decoder);
  
   /* no modification to wifi header should be done */
   
   return NULL;
}

/*
 * alignment function
 */
FUNC_ALIGNER(align_wifi)
{
   /* already aligned */
   return (32 - sizeof(struct wifi_header));
}

/* EOF */

// vim:ts=3:expandtab

