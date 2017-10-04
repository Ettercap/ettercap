/*
    ettercap -- dissector for Kerberos v5 - TCP 88 / UDP 88

    Copyright (C) Dhiru Kholia (dhiru at openwall.com)

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

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>
#include <ec_asn1.h>

/* protos */

FUNC_DECODER(dissector_kerberos);
void kerberos_init(void);

void __init kerberos_init(void)
{
   dissect_add("kerberosu", APP_LAYER_UDP, 88, dissector_kerberos);
   dissect_add("kerberost", APP_LAYER_TCP, 88, dissector_kerberos);
}

/* https://cwiki.apache.org/confluence/display/DIRxASN1/Kerberos

   KDC-REQ         ::= SEQUENCE {
        -- NOTE: first tag is [1], not [0]
        pvno            [1] INTEGER (5) ,
        msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
        padata          [3] SEQUENCE OF PA-DATA OPTIONAL
                            -- NOTE: not empty --,
        req-body        [4] KDC-REQ-BODY
   }

   KDC-REQ-BODY    ::= SEQUENCE {
        kdc-options             [0] KDCOptions,
        cname                   [1] PrincipalName OPTIONAL
                                    -- Used only in AS-REQ --,
        realm                   [2] Realm
                                    -- Server's realm
                                    -- Also client's in AS-REQ --,
        sname                   [3] PrincipalName OPTIONAL,
        from                    [4] KerberosTime OPTIONAL,
        till                    [5] KerberosTime,
        rtime                   [6] KerberosTime OPTIONAL,
        nonce                   [7] UInt32,
        etype                   [8] SEQUENCE OF Int32 -- EncryptionType
                                    -- in preference order --,
        addresses               [9] HostAddresses OPTIONAL,
        enc-authorization-data  [10] EncryptedData OPTIONAL
                                    -- AuthorizationData --,
        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
                                        -- NOTE: not empty
   }

   AS-REQ          ::= [APPLICATION 10] KDC-REQ */

FUNC_DECODER(dissector_kerberos)
{
   u_char *ptr;
   ptr = PACKET->DATA.data;
   struct asn1_hdr hdr;
   size_t length = PACKET->DATA.len;
   u_char *pos, *end;

   /* don't complain about unused var */
   (void)DECODE_DATA;
   (void)DECODE_DATALEN;
   (void)DECODED_LEN;

   if (length < 4)
      return NULL;

   /* Check for initial AS-REQ packet */
   if (FROM_CLIENT("kerberosu", PACKET) || FROM_CLIENT("kerberost", PACKET)) {
      pos = ptr;

      // APPLICATION 10
      if (asn1_get_next(pos, length, &hdr) < 0 || hdr.class != ASN1_CLASS_APPLICATION || hdr.tag != 10) {
         // Hack to skip over "Record Mark"
         pos = pos + 4;
         if (asn1_get_next(pos, length, &hdr) < 0 || hdr.class != ASN1_CLASS_APPLICATION || hdr.tag != 10) {
            return NULL;
         }
      }
      pos = hdr.payload;
      end = pos + hdr.length;
      if (end > pos + PACKET->DATA.len)
         return NULL;
      // KDC-REQ SEQUENCE
      if (asn1_get_next(pos, end - pos, &hdr) < 0 || hdr.class != ASN1_CLASS_UNIVERSAL || hdr.tag != ASN1_TAG_SEQUENCE) {
         return NULL;
      }
      pos = hdr.payload;

      // Seems like an AS-REQ message
      hook_point(HOOK_PROTO_KRB5, PACKET);
   } else {
      // KDC to client packet. BUG: if packet is modified here, then
      // we get invalid UDP checksums on the client side!
   }

   return NULL;
}

/* EOF */

// vim:ts=3:expandtab
