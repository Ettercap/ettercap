/*
    ettercap -- dissector ospf -- works over IP !

    Copyright (C) ALoR & NaGA
    Copyright (C) Dhiru Kholia (dhiru [at] openwall.com)

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

*/

/*
 * RFC: 2328
 *
 *      0                   1                   2                   3
 *       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *      |   Version #   |     Type      |         Packet length         |
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
 *
 * RFC 5709 is relevant for OSPFv2 HMAC-SHA Cryptographic Authentication.
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>

#define OSPF_NO_AUTH                0
#define OSPF_AUTH                   1  // OSPF_AUTH_SIMPLE
#define OSPF_AUTH_CRYPTOGRAPHIC     2

/* borrowed from GNU Zebra project */
#define BUFSIZE                     2048 /* big enough for OSPF */
#define OSPF_HEADER_SIZE            24U
#define OSPF_AUTH_SIMPLE_SIZE        8U
#define OSPF_AUTH_MD5_SIZE          16U
#define OSPF_AUTH_HMAC_SHA1_SIZE    20U
#define OSPF_AUTH_HMAC_SHA256_SIZE  32U
#define OSPF_AUTH_HMAC_SHA384_SIZE  48U
#define OSPF_AUTH_HMAC_SHA512_SIZE  64U

struct ospf_header
{
   u_int8 version;                       /* OSPF Version. */
   u_int8 type;                          /* Packet Type. */
   u_int16 length;                       /* Packet Length. */
   struct in_addr router_id;             /* Router ID. */
   struct in_addr area_id;               /* Area ID. */
   u_int16 checksum;                     /* Check Sum. */
   u_int16 auth_type;                    /* Authentication Type. */
   /* Authentication Data. */
   union
   {
      /* Simple Authentication. */
      u_char auth_data [OSPF_AUTH_SIMPLE_SIZE];
      /* Cryptographic Authentication. */
      struct
      {
         u_int16_t zero;                 /* Should be 0. */
         u_char key_id;                  /* Key ID. */
         u_char auth_data_len;           /* Auth Data Length. */
         u_int32_t crypt_seqnum;         /* Cryptographic Sequence Number. */
      } crypt;
   } u;
};

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
   dissect_add("ospf", PROTO_LAYER, NL_TYPE_OSPF, dissector_ospf);
}

/*
 * the passwords collected by ospf will not be logged
 * in logfile since it is not over TCP or UDP.
 * anyway we can print them in the user message window
 */

FUNC_DECODER(dissector_ospf)
{
   // DECLARE_DISP_PTR_END(ptr, end);  // this is broken!
   u_int8 *ptr = buf;
   char tmp[MAX_ASCII_ADDR_LEN];
   char pass[12];

   /* don't complain about unused var */
   (void) DECODED_LEN;
   // (void)end;

   /* skip empty packets */
   // if (PACKET->DATA.len == 0) {  // this is broken!
   if (buflen == 0) {
      return NULL;
   }

   DEBUG_MSG("OSPF --> dissector_ospf");

   struct ospf_header *ohdr = (struct ospf_header *)ptr;

   /* authentication */
   if ( ntohs(ohdr->auth_type) == OSPF_AUTH_CRYPTOGRAPHIC ) {
        unsigned int i = 0;

        unsigned int length = ntohs(ohdr->length);
        unsigned auth_data_len = ohdr->u.crypt.auth_data_len;
        int type = 0;

        /* validate the packet */
        if (length * 2 > BUFSIZE)
                return NULL;
        if (length > buflen)
                return NULL;

        if (auth_data_len == OSPF_AUTH_MD5_SIZE) {
                DISSECT_MSG("OSPF-%s-%d:$netmd5$",
                        ip_addr_ntoa(&PACKET->L3.dst, tmp),
                        ntohs(PACKET->L4.dst));
        } else if (auth_data_len == OSPF_AUTH_HMAC_SHA1_SIZE) {
                type = 1;
        } else if (auth_data_len == OSPF_AUTH_HMAC_SHA256_SIZE) {
                type = 2;
        } else if (auth_data_len == OSPF_AUTH_HMAC_SHA384_SIZE) {
                type = 3;
        } else if (auth_data_len == OSPF_AUTH_HMAC_SHA512_SIZE) {
                type = 4;
        } else {
                return NULL;
        }

        if (type != 0) {
                DISSECT_MSG("OSPF-%s-%d:$ospf$%d$",
                        ip_addr_ntoa(&PACKET->L3.dst, tmp),
                        ntohs(PACKET->L4.dst), type);
        }

        for (i=0; i<length; i++) {
           if (ptr+i == NULL)
              return NULL;

           DISSECT_MSG("%02x", *(ptr+i));
        }
        DISSECT_MSG("$");
        for (i=length; i<length+auth_data_len; i++) {
           if (ptr+i == NULL)
              return NULL;

           DISSECT_MSG("%02x", *(ptr+i));
        }
        DISSECT_MSG("\n");


   } else if ( ntohs(ohdr->auth_type) == OSPF_AUTH ) {  /* Simple Authentication */
      DEBUG_MSG("\tDissector_ospf PASS");

      /*
       * we use a local variable since this does
       * not need to reach the top half
       */
      char o[OSPF_AUTH_SIMPLE_SIZE];
      snprintf(o, OSPF_AUTH_SIMPLE_SIZE, "%s", ohdr->u.auth_data);
      strncpy(pass, o, OSPF_AUTH_SIMPLE_SIZE);

      DISSECT_MSG("OSPF : %s:%d -> AUTH: %s \n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                ntohs(PACKET->L4.dst),
                pass);
   }

   /* no authentication */
   else if ( ntohs(ohdr->auth_type) == OSPF_NO_AUTH ) {
      DEBUG_MSG("\tDissector_ospf NO AUTH");
      strncpy(pass, "No Auth", 8);

      DISSECT_MSG("OSPF : %s:%d -> AUTH: %s \n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                ntohs(PACKET->L4.dst),
                pass);
   }

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

