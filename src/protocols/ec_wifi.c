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

    $Id: ec_wifi.c,v 1.14 2004/05/13 15:15:16 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_capture.h>
#include <ec_checksum.h>

#ifdef HAVE_OPENSSL
   #include <openssl/rc4.h>
#endif

/* globals */

struct wifi_header {
   u_int8   type;
      #define WIFI_DATA    0x08
      #define WIFI_BACON   0x80
      #define WIFI_ACK     0xd4
   u_int8   control;
      #define WIFI_STA_TO_STA 0x00  /* ad hoc mode */
      #define WIFI_STA_TO_AP  0x01
      #define WIFI_AP_TO_STA  0x02
      #define WIFI_AP_TO_AP   0x03
      #define WIFI_WEP        0x40
   u_int16  duration;
   /*
    * the following three fields has different meanings
    * depending on the control value... argh !!
    *
    *    - WIFI_STA_TO_STA  (ad hoc)
    *       ha1 -> dst 
    *       ha2 -> src
    *       ha3 -> bssid
    *    - WIFI_STA_TO_AP  
    *       ha1 -> bssid  
    *       ha2 -> src
    *       ha3 -> dst
    *    - WIFI_AP_TO_AP
    *       ha1 -> rx 
    *       ha2 -> tx
    *       ha3 -> dst
    *       ha4 -> src
    *    - WIFI_AP_TO_STA
    *       ha1 -> dst
    *       ha2 -> bssid
    *       ha3 -> src
    */    
   u_int8   ha1[ETH_ADDR_LEN];
   u_int8   ha2[ETH_ADDR_LEN];
   u_int8   ha3[ETH_ADDR_LEN];
   u_int16  seq;
   /* this field is present only if control is WIFI_AP_TO_AP */
   /* u_int8   ha3[ETH_ADDR_LEN]; */
};

struct llc_header {
   u_int8   dsap;
   u_int8   ssap;
   u_int8   control;
   u_int8   org_code[3];
   u_int16  proto;
};

#define IV_LEN 3

struct wep_header {
   u_int8   init_vector[IV_LEN];
   u_int8   key;
};

/* encapsulated ethernet */
u_int8 WIFI_ORG_CODE[3] = {0x00, 0x00, 0x00};

/* protos */

FUNC_DECODER(decode_wifi);
FUNC_ALIGNER(align_wifi);
void wifi_init(void);
static int wep_decrypt(u_char *buf, size_t len);

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
   struct wep_header *wep;
   FUNC_DECODER_PTR(next_decoder) = NULL;

   DECODED_LEN = sizeof(struct wifi_header);
      
   wifi = (struct wifi_header *)DECODE_DATA;
   
   /* we are interested only in wifi data packets */
   if (wifi->type != WIFI_DATA) {
      return NULL;
   }

   /* 
    * capture only "complete" and not retransmitted packets 
    * we don't want to deal with fragments (0x04) or retransmission (0x08) 
    */
   switch (wifi->control & 0x03) {
      
      case WIFI_STA_TO_STA:
         memcpy(PACKET->L2.src, wifi->ha2, ETH_ADDR_LEN);
         memcpy(PACKET->L2.dst, wifi->ha1, ETH_ADDR_LEN);
         break;
   
   
      case WIFI_STA_TO_AP:
         memcpy(PACKET->L2.src, wifi->ha2, ETH_ADDR_LEN);
         memcpy(PACKET->L2.dst, wifi->ha3, ETH_ADDR_LEN);
         break;
   
      case WIFI_AP_TO_STA:
         memcpy(PACKET->L2.src, wifi->ha3, ETH_ADDR_LEN);
         memcpy(PACKET->L2.dst, wifi->ha1, ETH_ADDR_LEN);
         break;
         
      case WIFI_AP_TO_AP:
         /* 
          * XXX - fix this or ignore this case...
          *
          * SHIT !! we have alignment problems here...
          */
#if 0         
         /* 
          * get the logical link layer header 
          * there is one more field (ha4) in this case
          */
         llc = (struct llc_header *)((u_char *)wifi + sizeof(struct wifi_header) + ETH_ADDR_LEN);
         DECODED_LEN += sizeof(struct llc_header) + ETH_ADDR_LEN;
         
         memcpy(PACKET->L2.src, (char *)(wifi + 1), ETH_ADDR_LEN);
         memcpy(PACKET->L2.dst, wifi->ha3, ETH_ADDR_LEN);
#endif
         return NULL;
         break;
      
      default:
         return NULL;
   }
  
   /* the frame is crypted with WEP */
   if (wifi->control & WIFI_WEP) {
      
      /* get the WEP header */
      wep = (struct wep_header *)(wifi + 1);
      DECODED_LEN += sizeof(struct wep_header);

      /* decrypt the packet */
      if (wep_decrypt((u_char *)wep, DECODE_DATALEN - DECODED_LEN) != ESUCCESS)
         return NULL;
      
      /* get the logical link layer header */
      llc = (struct llc_header *)(wep + 1);
      DECODED_LEN += sizeof(struct llc_header);
   } else {
   
      /* get the logical link layer header */
      llc = (struct llc_header *)(wifi + 1);
      DECODED_LEN += sizeof(struct llc_header);
   }
   
   /* org_code != encapsulated ethernet not yet supported */
   if (memcmp(llc->org_code, WIFI_ORG_CODE, 3))
      //return NULL;
      NOT_IMPLEMENTED();
      
   /* fill the packet object with sensitive data */
   PACKET->L2.header = (u_char *)DECODE_DATA;
   PACKET->L2.proto = IL_TYPE_WIFI;
   PACKET->L2.len = DECODED_LEN;

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
   return (32 - sizeof(struct wifi_header) - sizeof(struct llc_header));
}


/*
 * WEP decrypt function
 */
static int wep_decrypt(u_char *buf, size_t len)
{
#ifdef HAVE_OPENSSL_NOT_YET_IMPLEMENTED
   RC4_KEY key;
   u_char seed[32]; /* 256 bit for the wep key */
   struct wep_header *wep;
   u_char tmpbuf[len];

   u_char wkey[] = "12345";
   size_t wlen = 5;
 
   USER_MSG("WEP: detected crypted packet\n");
   
   /* get the wep header */
   wep = (struct wep_header *)buf;
   len -= sizeof(struct wep_header);

   /* copy the IV in the first 24 bit of the RC4 seed */
   memcpy(seed, wep->init_vector, IV_LEN);

   /* 
    * complete the seed with 40 or 104 bit from the secret key 
    * to have a 64 or 128 bit seed 
    */
   memcpy(seed + IV_LEN, wkey, wlen);
  
   /* initialize the RC4 key */
   RC4_set_key(&key, IV_LEN + wlen, seed);
  
   /* at the end of the frame there is a plain CRC checksum */
   len -= sizeof(u_int32);

   /* decrypt the frame */
   RC4(&key, len, (u_char *)(wep + 1), tmpbuf);
   
   /* append the crc check at the end of the buffer */
   memcpy(tmpbuf + len, (u_char *)(wep + 1) + len, sizeof(u_int32));
         
   /* check if the decryption was successfull */
   if (CRC_checksum(tmpbuf, len + sizeof(u_int32), CRC_INIT) != CRC_RESULT) {
      USER_MSG("WEP: invalid key, tha packet was skipped\n");
      return -ENOTHANDLED;
   }
  
   /* copy the decrypted packet over the original one */
   memcpy((u_char *)(wep + 1), tmpbuf, len);
   
   return ESUCCESS;
#else
   return -EFATAL;
#endif
}

/* EOF */

// vim:ts=3:expandtab

