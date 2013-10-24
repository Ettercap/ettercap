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
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>

#define OSPF_AUTH_LEN            8
#define OSPF_NO_AUTH             0
#define OSPF_AUTH                1  // OSPF_AUTH_SIMPLE
#define OSPF_AUTH_CRYPTOGRAPHIC  2

struct ospf_hdr {
   u_int8   ver;
   u_int8   type;
   u_int16  len;
   u_int32  rid;
   u_int32  aid;
   u_int16  csum;
   u_int16  auth_type;
   u_int32  auth1;
   u_int32  auth2;
};

static char itoa16[16] =  "0123456789abcdef";

static inline void hex_encode(unsigned char *str, int len, unsigned char *out)
{
   int i;
   for (i = 0; i < len; ++i) {
      out[0] = itoa16[str[i]>>4];
      out[1] = itoa16[str[i]&0xF];
      out += 2;
   }
}

/* borrowed from GNU Zebra project */
#define BUFSIZE                  2048 /* big enough for OSPF */
#define OSPF_HEADER_SIZE         24U
#define OSPF_AUTH_SIMPLE_SIZE     8U
#define OSPF_AUTH_MD5_SIZE       16U

struct ospf_header
{
   u_int8 version;                       /* OSPF Version. */
   u_int8 type;                          /* Packet Type. */
   u_int16_t length;                     /* Packet Length. */
   struct in_addr router_id;             /* Router ID. */
   struct in_addr area_id;               /* Area ID. */
   u_int16_t checksum;                   /* Check Sum. */
   u_int16_t auth_type;                  /* Authentication Type. */
   u_int16_t zero;                       /* Should be 0. */
   u_int8 key_id;                        /* Key ID. */
   u_int8 auth_data_len;                 /* Auth Data Length. */
   u_int32_t crypt_seqnum;               /* Cryptographic Sequence Number. */
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
   struct ospf_hdr *ohdr;
   u_int8 *ptr = buf;
   char tmp[MAX_ASCII_ADDR_LEN];
   char pass[12];

   /* don't complain about unused var */
   // (void)end;

   /* skip empty packets */
   // if (PACKET->DATA.len == 0) {  // this is broken!
   if (buflen == 0) {
      return NULL;
   }

   DEBUG_MSG("OSPF --> dissector_ospf");

   ohdr = (struct ospf_hdr *)ptr;

   /* authentication */
   if ( ntohs(ohdr->auth_type) == OSPF_AUTH_CRYPTOGRAPHIC ) {
        struct ospf_header *oh = (struct ospf_header *)ptr;
        unsigned char buf1[BUFSIZE] = { 0 };
        unsigned char buf2[BUFSIZE] = { 0 };

        int length = ntohs(ohdr->len);

        if (oh->auth_data_len != OSPF_AUTH_MD5_SIZE) {
                return NULL;
        }

        /* validate the packet */
        if (length * 2 > BUFSIZE)
                return NULL;
        if (length > buflen)
                return NULL;

        hex_encode(ptr, length, buf1);
        hex_encode(ptr + length, OSPF_AUTH_MD5_SIZE, buf2);

        DISSECT_MSG("OSPF-%s-%d:$netmd5$%s$%s\n",
                ip_addr_ntoa(&PACKET->L3.dst, tmp),
                ntohs(PACKET->L4.dst),
                buf1, buf2);
   } else if ( ntohs(ohdr->auth_type) == OSPF_AUTH ) {
      DEBUG_MSG("\tDissector_ospf PASS");

      /*
       * we use a local variable since this does
       * not need to reach the top half
       */
      char o[OSPF_AUTH_LEN];
      snprintf(o, OSPF_AUTH_LEN, "%s", (char*)&(ohdr->auth1));
      strncpy(pass, o, OSPF_AUTH_LEN);

      DISSECT_MSG("OSPF : %s:%d -> AUTH: %s \n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                ntohs(PACKET->L4.dst),
                pass);
   }

   /* no authentication */
   else if ( ntohs(ohdr->auth_type) == OSPF_NO_AUTH ) {
      DEBUG_MSG("\tDissector_ospf NO AUTH");
      strncpy(pass, "No Auth", 7);

      DISSECT_MSG("OSPF : %s:%d -> AUTH: %s \n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                ntohs(PACKET->L4.dst),
                pass);
   }

   return NULL;
}


/* EOF */

// vim:ts=3:expandtab

