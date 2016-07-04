/*
 * ettercap -- dissector for Oracle O5LOGON protocol -- TCP 1521
 *
 * Copyright (c) 2012-2014 Dhiru Kholia (dhiru at openwall.com)
 * Copyright (c) 2016 magnum
 *
 * Tested with Oracle 11gR1 and 11gR2 64-bit server and Linux +
 * Windows SQL*Plus clients. Now also works with Oracle 12. That
 * version avoids the known-plain vulnerability from PKCS#7 padding
 * so more fields are needed for a full attack.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <ec.h>
#include <ec_decode.h>
#include <ec_dissect.h>
#include <ec_session.h>

//#define O5DEBUG

/* globals */

struct o5logon_status {
   u_char user[129];
   u_char srv_addr[22];
   u_char srv_sk[97];
   u_char cli_sk[97];
   u_char pw[256];
   u_char salt[21];
   struct {
      u_int user : 1;
      u_int c_ano : 1;
      u_int c_sk : 1;
      u_int pw : 1;
      u_int s_ano : 1;
      u_int vfr : 1;
      u_int s_sk : 1;
      u_int pkcs : 2;
   } flags;
};

/* PKCS#7 padding used? */
#define MAYBE 0
#define YES   1
#define NO    2

/* protos */

FUNC_DECODER(dissector_o5logon);
void o5logon_init(void);

/************************************************/

#undef memrchr
#define memrchr my_memrchr

static void *memrchr(const void *s, u_char c, size_t n)
{
   const u_char *cp;

   if (n != 0) {
      cp = (u_char*)s + n;
      do {
         if (*(--cp) == (u_char)c)
            return (void*)cp;
      } while (--n != 0);
   }

   return NULL;
}

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init o5logon_init(void)
{
   dissect_add("o5logon", APP_LAYER_TCP, 1521, dissector_o5logon);
}

FUNC_DECODER(dissector_o5logon)
{
   DECLARE_DISP_PTR_END(ptr, end);
   struct ec_session *s = NULL;
   void *ident = NULL;
   char tmp[MAX_ASCII_ADDR_LEN];
   struct o5logon_status *conn_status = NULL;

   //suppress unused warning
   (void)end;
   (void)DECODE_DATA;
   (void)DECODE_DATALEN;
   (void)DECODED_LEN;

   dissect_create_ident(&ident, PACKET, DISSECT_CODE(dissector_o5logon));

   if (FROM_CLIENT("o5logon", PACKET)) {

      if (session_get(&s, ident, DISSECT_IDENT_LEN) == -E_NOTFOUND) {
         dissect_create_session(&s, PACKET, DISSECT_CODE(dissector_o5logon));
         SAFE_CALLOC(s->data, 1, sizeof(struct o5logon_status));
         session_put(s);
      }

      /* Fetch state of existing session */
      conn_status = (struct o5logon_status*)s->data;

      if (PACKET->DATA.len == 0) {
         /*
          * We output this packet just in case, but we may see more data
          * later and output another copy with more fields. See issue #741.
          */
         if (conn_status->flags.pkcs != NO && conn_status->flags.user && conn_status->flags.s_sk && conn_status->flags.vfr) {
            DISSECT_MSG("%s@%s:$o5logon$%s*%s\n", conn_status->user, conn_status->srv_addr, conn_status->srv_sk, conn_status->salt);
         }
         if (PACKET->L4.flags & (TH_FIN | TH_RST)) {
            dissect_wipe_session(PACKET, DISSECT_CODE(dissector_o5logon));
         }
         SAFE_FREE(ident);
         return NULL;
      }

      /* Interesting packets have len >= 24 */
      if (PACKET->DATA.len < 24) {
         SAFE_FREE(ident);
         return NULL;
      }

      u_char *ano;

      if ((ano = memmem(ptr, PACKET->DATA.len, "\xde\xad\xbe\xef", 4))) {
         conn_status->flags.c_ano = 1;

         ano += 25;
#ifdef O5DEBUG
         DISSECT_MSG("client ver %u.%u.%u.%u.%u (PKCS)\n", ano[0], ano[1] >> 4, ano[1] & 15 , ano[2], ano[3]);
#endif
         if ((ano[0] << 16) + (ano[1] << 8) + ano[2] < 0x0a2003) {
            conn_status->flags.pkcs = YES;
         }
      }
      else {
         u_char *csk;
         u_char *pw;

         if (conn_status->flags.user == 0) {
            u_char *sp;

            if ((sp = memmem(ptr, PACKET->DATA.len, "AUTH_TERMINAL", 13))) {
               /* Find username, best effort */
               /* Names are 1 to 30 bytes and may include multibyte */
               u_char *end = sp - 1;
               while(end > ptr && *end < 0x20) {
                  end--;
               }
               while(end > ptr && *end == '\'' && end[1] == 0) {
                  end--;
               }
               u_char *start = end;
               while(start > ptr && *start != 0xff && *start >= 0x20) {
                  start--;
               }
               ++start;
               size_t length = (size_t)(end - start) + 1;

               strncpy((char*)conn_status->user, (char*)start, sizeof(conn_status->user) - 1);
               if (length < sizeof(conn_status->user))
                  conn_status->user[length] = 0;

#ifdef O5DEBUG
               DISSECT_MSG("%s:%d->%s:%d Got username %s%s\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst), conn_status->user, conn_status->flags.c_ano == 1 ? "" : "(no ANO seen)");
#endif
               conn_status->flags.user = 1;
            }
         }

         if (conn_status->flags.pw == 0 &&
            (pw = memmem(ptr, PACKET->DATA.len, "AUTH_PASSWORD", 13))) {
            char password[256 + 1];
            int pwlen = 0;

            if (memrchr(pw, 0x60, 24)) {
               pwlen = 0x60;
               pw = memrchr(pw, 0x60, 24);
            }
            else
               pwlen = 0x40;

            if ((pw = memrchr(pw, 0x40, 24))) {
               int i;

               pw++;
               for (i = 0; i < 2 * pwlen; i++) {
                  while (*pw == ' ')
                     pw++;
                  password[i] = *pw++;
               }
               password[pwlen] = 0;
               strncpy(conn_status->pw, password, sizeof(conn_status->pw));
#ifdef O5DEBUG
               DISSECT_MSG("%s:%d->%s:%d Got encrypted password\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst));
#endif
               conn_status->flags.pw = 1;
            }
         }

         if (conn_status->flags.c_sk == 0 &&
            (csk = memmem(ptr, PACKET->DATA.len, "AUTH_SESSKEY", 12))) {
            u_char sk[97];
            int i;

            if (memrchr(csk, 0x40, 20))
               csk = memrchr(csk, 0x40, 20);
            else
               csk = memrchr(csk, 0x60, 20);

            if (csk) {
               csk++;
               for (i = 0; i < 96; i++) {
                  while (*csk == ' ')
                     csk++;
                  sk[i] = *csk++;
               }
               sk[96] = 0;
               strncpy(conn_status->cli_sk, sk, sizeof(conn_status->cli_sk));
               conn_status->flags.c_sk = 1;
#ifdef O5DEBUG
               DISSECT_MSG("%s:%d->%s:%d Got client session key\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst));
#endif
            }
#ifdef O5DEBUG
            else {
               DISSECT_MSG("%s:%d->%s:%d saw AUTH_SESSKEY but couldn't parse client session key?\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst));
            }
#endif
         }
      }

      if (conn_status && conn_status->flags.user && conn_status->flags.s_sk && conn_status->flags.vfr && conn_status->flags.pw && conn_status->flags.c_sk) {
         DISSECT_MSG("%s@%s:$o5logon$%s*%s*%s*%s\n", conn_status->user, conn_status->srv_addr, conn_status->srv_sk, conn_status->salt, conn_status->pw, conn_status->cli_sk);
         dissect_wipe_session(PACKET, DISSECT_CODE(dissector_o5logon));
      }
   }
   else {   /* From server */

      if (session_get(&s, ident, DISSECT_IDENT_LEN) == E_SUCCESS) {

         conn_status = (struct o5logon_status*)s->data;

         if (conn_status->flags.s_ano == 0) {
            if (PACKET->DATA.len > 32) {
               u_char *ano = memmem(ptr, PACKET->DATA.len, "\xde\xad\xbe\xef", 4);
               if (ano) {
                  ano += 25;
                  conn_status->flags.s_ano = 1;
#ifdef O5DEBUG
                  DISSECT_MSG("server ver %u.%u.%u.%u.%u\n", ano[0], ano[1] >> 4, ano[1] & 15 , ano[2], ano[3]);
#endif
                  if (ano[0] >= 0x0c) {
                     conn_status->flags.pkcs = NO;
                  }
                  else if ((ano[0] << 16) + (ano[1] << 8) + ano[2] < 0x0a2003) {
                     conn_status->flags.pkcs = YES;
                  }
               }
            }
         }

         if (PACKET->DATA.len > 32) {
            if (conn_status->flags.vfr == 0) {
               u_char salt[21];
               u_char *saltp = memmem(ptr, PACKET->DATA.len, "AUTH_VFR_DATA", 13);

               if (saltp)
                  saltp = memrchr(saltp, 0x14, 20);

               if (saltp) {
                  saltp++;
                  strncpy((char*)salt, (char*)saltp, 20);
                  salt[20] = 0;

                  strncpy(conn_status->salt, salt, sizeof(conn_status->salt));
#ifdef O5DEBUG
                  DISSECT_MSG("%s:%d->%s:%d Got VFR\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst));
#endif
                  conn_status->flags.vfr = 1;
               }
            }

            if (conn_status->flags.s_sk == 0) {
               u_char sk[97];
               u_char *skp = memmem(ptr, PACKET->DATA.len, "AUTH_SESSKEY", 12);
               int i;

               if (skp) {
                  if (memrchr(skp, 0x40, 20))
                     skp = memrchr(skp, 0x40, 20);
                  else
                     skp = memrchr(skp, 0x60, 20);
               }

               if (skp) {
                  skp++;
                  for (i = 0; i < 96; i++) {
                     while (*skp == ' ')
                        skp++;
                     sk[i] = *skp++;
                  }
                  sk[96] = 0;

                  strncpy(conn_status->srv_addr, ip_addr_ntoa(&PACKET->L3.src, tmp), sizeof(conn_status->srv_addr));
                  strncpy(conn_status->srv_sk, sk, sizeof(conn_status->srv_sk));
#ifdef O5DEBUG
                  DISSECT_MSG("%s:%d->%s:%d Got server session key\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst));
#endif
                  conn_status->flags.s_sk = 1;
               }
            }
         }

         if (memmem(ptr, PACKET->DATA.len, "invalid username", 16)) {
            DISSECT_MSG("Login to %s:%d as %s failed! Invalid username or password\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), conn_status->user);
            conn_status->flags.user = 0;
            conn_status->flags.s_sk = 0;
            conn_status->flags.vfr = 0;
            conn_status->flags.pw = 0;
            conn_status->flags.c_sk = 0;
         }
         else if (memmem(ptr, PACKET->DATA.len, "account is locked", 17)) {
            DISSECT_MSG("Login to %s:%d as %s failed, account locked!\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), conn_status->user);
            conn_status->flags.user = 0;
            conn_status->flags.s_sk = 0;
            conn_status->flags.vfr = 0;
            conn_status->flags.pw = 0;
            conn_status->flags.c_sk = 0;
         }

#ifdef O5DEBUG
      } else {
         DISSECT_MSG("No session; %s:%d -> %s:%d\n", ip_addr_ntoa(&PACKET->L3.src, tmp), ntohs(PACKET->L4.src), ip_addr_ntoa(&PACKET->L3.dst, tmp), ntohs(PACKET->L4.dst));
#endif
      }
   }

   SAFE_FREE(ident);
   return NULL;
}

// vim:ts=3:expandtab
