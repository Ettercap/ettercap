/*
    ettercap -- dissector icq -- TCP 5190

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

    $Id: ec_icq.c,v 1.1 2003/09/29 12:20:57 alor Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>

/* globals */

struct tlv_hdr {
   u_int16 type;
      #define TLV_LOGIN 1
      #define TLV_PASS  2
   u_int16 len;
};

struct flap_hdr {
   u_int8 cmd;
   u_int8 chan;
      #define FLAP_CHAN_LOGIN 1
   u_int16 seq;
   u_int16 dlen;
};


/* protos */

FUNC_DECODER(dissector_icq);
void icq_init(void);
void decode_pwd(char *pwd, char *outpwd);

/************************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init icq_init(void)
{
   dissect_add("icq", APP_LAYER_TCP, 5190, dissector_icq);
}

FUNC_DECODER(dissector_icq)
{
   DECLARE_DISP_PTR_END(ptr, end);
   char tmp[MAX_ASCII_ADDR_LEN];
   struct flap_hdr *fhdr;
   struct tlv_hdr *thdr;
   char *user, *pwdtemp;

   /* don't complain about unused var */
   (void)end;

   /* parse only version 7/8 */
   if (ptr[0] != 0x2a || ptr[1] > 4) 
      return NULL;
  
   DEBUG_MSG("ICQ --> TCP dissector_icq [%d.%d]", ptr[0], ptr[1]);
   
   /* we try to recognize the protocol */
   fhdr = (struct flap_hdr *) ptr;

   /* login sequence */
   if (fhdr->chan == FLAP_CHAN_LOGIN) {

      /* move the pointer */
      ptr += sizeof(struct flap_hdr);
      thdr = (struct tlv_hdr *) ptr;
      
      /* we need server HELLO (0000 0001) */
      if (ntohs(thdr->type) != 0 || ntohs(thdr->len) != 1) 
         return NULL;

      /* move the pointer */
      thdr = thdr + 1;

      //DEBUG_MSG("\tdissector_icq : TLV TYPE [%d] should be [%d]", ntohs(thdr->type), TLV_LOGIN);

      /* catch the login */
      if (ntohs(thdr->type) != TLV_LOGIN)
         return NULL;
      
      DEBUG_MSG("\tDissector_icq - LOGIN ");

      /* point to the user */
      user = (char *)(thdr + 1);

      /* move the pointer */
      thdr = (struct tlv_hdr *) ((char *)thdr + sizeof(struct tlv_hdr) + ntohs(thdr->len));

      DEBUG_MSG("\tdissector_icq : TLV TYPE [%d] should be [%d]", ntohs(thdr->type), TLV_PASS);
            
      /* catch the pass */
      if (ntohs(thdr->type) != TLV_PASS)
         return NULL;

      DEBUG_MSG("\tDissector_icq - PASS");
      
      /* use a temp buff to decript the password */
      pwdtemp = strdup((char *)(thdr + 1));

      SAFE_CALLOC(PACKET->DISSECTOR.pass, strlen(pwdtemp), sizeof(char));

      /* decode the password */
      decode_pwd(pwdtemp, PACKET->DISSECTOR.pass);
      /* save the user */
      PACKET->DISSECTOR.user = strdup(user);

      SAFE_FREE(pwdtemp);
      
      /* move the pointer */
      thdr = (struct tlv_hdr *) ((char *)thdr + sizeof(struct tlv_hdr) + ntohs(thdr->len));

      PACKET->DISSECTOR.info = strdup((char *)(thdr + 1));
      
      USER_MSG("ICQ : %s:%d -> USER: %s  PASS: %s\n", ip_addr_ntoa(&PACKET->L3.dst, tmp),
                                    ntohs(PACKET->L4.dst), 
                                    PACKET->DISSECTOR.user,
                                    PACKET->DISSECTOR.pass);

   } else {
         
         return 0;  /* not yet implemented */

#if 0         
         SNAC_HEADER *snac;
         u_char *p, *end;
         char *uin, *message;
         
         memcpy(collector, payload, sniff_data_to_ettercap->datasize);

         end = collector + sniff_data_to_ettercap->datasize;
         
         flap = (FLAP_HEADER *) collector;
         snac = (SNAC_HEADER *) (flap + 1);
         
         if (snac->family[1] != 4 || snac->command[1] != 6) return 0;   /* not a message */
        
         DEBUG_MSG("ICQ DATA -- SNAC 4 6");
         
         for(p = (u_char *)snac; memcmp(p, "\x00\x00\x00\x01", 4) && p < end; p++); /* find the server hello */
         if (p == end) return 0;
         p += 4;

         DEBUG_MSG("ICQ DATA -- UIN");
         
         uin = strdup ( p + 1 );

         for(p = (u_char *)snac; memcmp(p, "\x00\x00\xff\xff", 4) && p < end; p++); /* find the message */
         if (p == end) return 0;
         p += 4;

         DEBUG_MSG("ICQ DATA -- message");
         
         message = strdup ( p );

         memset(sniff_data_to_ettercap->data, 0, sizeof(sniff_data_to_ettercap->data));
         sprintf(sniff_data_to_ettercap->data, "*** ICQ MESSAGE ***\n To: %s\n\n Message: %s\n\n", uin, message);
         sniff_data_to_ettercap->datasize = strlen(sniff_data_to_ettercap->data);

         free(uin);
         free(message);
#endif
         
   }

   return NULL;
}

/*
 * decode the crypted password 
 */
void decode_pwd(char *pwd, char *outpwd)
{
   size_t x;
   u_char pwd_key[] = {
      0xF3, 0x26, 0x81, 0xC4, 0x39, 0x86, 0xDB, 0x92,
      0x71, 0xA3, 0xB9, 0xE6, 0x53, 0x7A, 0x95, 0x7C
   };
   
   for( x = 0; x < strlen(pwd); x++)
      *(outpwd + x) = pwd[x] ^ pwd_key[x];
   
   return;
}

/* EOF */

// vim:ts=3:expandtab

