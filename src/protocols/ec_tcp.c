/*
    ettercap -- TCP decoder module

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

    $Id: ec_tcp.c,v 1.17 2003/09/30 11:30:55 lordnaga Exp $
*/

#include <ec.h>
#include <ec_decode.h>
#include <ec_fingerprint.h>
#include <ec_checksum.h>
#include <ec_session.h>
#include <ec_inject.h>


/* globals */

struct tcp_header {
   u_int16  sport;      /* source port */
   u_int16  dport;      /* destination port */
   u_int32  seq;        /* sequence number */
   u_int32  ack;        /* acknowledgement number */
#ifndef WORDS_BIGENDIAN
   u_int8   x2:4;       /* (unused) */
   u_int8   off:4;      /* data offset */
#else
   u_int8   off:4;      /* data offset */
   u_int8   x2:4;       /* (unused) */
#endif
   u_int8   flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PSH  0x08
#define TH_ACK  0x10
#define TH_URG  0x20
   u_int16  win;        /* window */
   u_int16  csum;       /* checksum */
   u_int16  urp;        /* urgent pointer */
};

/* tcp options */
#define TCPOPT_EOL              0
#define TCPOPT_NOP              1
#define TCPOPT_MAXSEG           2
#define TCPOPT_WSCALE           3
#define TCPOPT_SACKOK           4
#define TCPOPT_TIMESTAMP        8

/* Session data structure */
struct tcp_half_status {
   u_int32  last_seq;
   int32    seq_adj;
};

struct tcp_status {
   struct tcp_half_status way[2];
};

/* session identifier */
struct tcp_ident {
   u_int32 magic;
      #define TCP_MAGIC  0x0400e77e
   struct ip_addr L3_src;
   struct ip_addr L3_dst;
   u_int16 L4_src;
   u_int16 L4_dst;
};

#define TCP_IDENT_LEN sizeof(struct tcp_ident)


/* protos */

FUNC_DECODER(decode_tcp);
FUNC_INJECTOR(inject_tcp);
void tcp_init(void);
int tcp_match(void *id_sess, void *id_curr);
void tcp_create_session(struct session **s, struct packet_object *po);
size_t tcp_create_ident(void **i, struct packet_object *po);            
int tcp_find_direction(void *ids, void *id);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered decoder
 */

void __init tcp_init(void)
{
   add_decoder(PROTO_LAYER, NL_TYPE_TCP, decode_tcp);
   add_injector(CHAIN_ENTRY, NL_TYPE_TCP, inject_tcp);
}


FUNC_DECODER(decode_tcp)
{
   FUNC_DECODER_PTR(next_decoder);
   struct tcp_header *tcp;
   u_char *opt_start, *opt_end;
   struct session *s = NULL;
   void *ident = NULL;
   struct tcp_status *status;
   int direction;

   tcp = (struct tcp_header *)DECODE_DATA;
   
   opt_start = (u_char *)(tcp + 1);
   opt_end = (u_char *)((int)tcp + tcp->off * 4);

   DECODED_LEN = (tcp->off * 4);

   /* source and dest port */
   PACKET->L4.src = tcp->sport;
   PACKET->L4.dst = tcp->dport;
  
   PACKET->L4.len = DECODED_LEN;
   PACKET->L4.header = (u_char *)DECODE_DATA;
   
   if (opt_start != opt_end) {
      PACKET->L4.options = opt_start;
      PACKET->L4.optlen = opt_end - opt_start;
   } else {
      PACKET->L4.options = NULL;
      PACKET->L4.optlen = 0;
   }
   
   /* this is TCP */
   PACKET->L4.proto = NL_TYPE_TCP;
   
   /* save the flags */
   PACKET->L4.flags = tcp->flags;

   /* set up the data poiters */
   PACKET->DATA.data = opt_end;
   PACKET->DATA.len = PACKET->L3.payload_len - DECODED_LEN;

   /* create the buffer to be displayed */
   packet_disp_data(PACKET, PACKET->DATA.data, PACKET->DATA.len);
   
   /* 
    * if the checsum is wrong, don't parse it (avoid ettercap spotting) 
    * the checksum is should be 0 and not equal to ip->csum ;)
    */
   if (L4_checksum(PACKET) != 0) {
      char tmp[MAX_ASCII_ADDR_LEN];
      USER_MSG("Invalid TCP packet from %s:%d : csum [%#x] (%#x)\n", ip_addr_ntoa(&PACKET->L3.src, tmp),
                                    ntohs(tcp->sport), L4_checksum(PACKET), ntohs(tcp->csum) );
      return NULL;
   }
     
   /* 
    * complete the passive fingerprint (started at IP layer)
    * we are intereste only in SYN or SYN+ACK packets 
    * else we can destroy the fingerprint
    */
   if ( tcp->flags & TH_SYN ) {
   
      fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_WINDOW, ntohs(tcp->win));
      fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_TCPFLAG, (tcp->flags & TH_ACK) ? 1 : 0);
      /* this is added to the len of ip header (automatic) */
      fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_LT, tcp->off * 4);
   
      while (opt_start < opt_end) {
         switch (*opt_start) {
            case TCPOPT_EOL: 
               /* end option EXIT */
               opt_start = opt_end;
               break;
            case TCPOPT_NOP:
               fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_NOP, 1);
               opt_start++;
               break;
            case TCPOPT_SACKOK:
               fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_SACK, 1);
               opt_start += 2;
               break;
            case TCPOPT_MAXSEG:
               opt_start += 2;
               fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_MSS, ntohs(ptohs(opt_start)));
               opt_start += 2;
               break;
            case TCPOPT_WSCALE:
               opt_start += 2;
               fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_WS, *opt_start);
               opt_start++;
               break;
            case TCPOPT_TIMESTAMP:
               fingerprint_push(PACKET->PASSIVE.fingerprint, FINGER_TIMESTAMP, 1);
               opt_start++;
               opt_start += (*opt_start - 1);
               break;
            default:
               opt_start++;
               if (*opt_start > 0)
                  opt_start += (*opt_start - 1);
               break;
         }
      }
      
   } else {
      /* not an interesting packet */
      memset(PACKET->PASSIVE.fingerprint, 0, FINGER_LEN);
   }
  
   /* HOOK POINT: PACKET_TCP */
   hook_point(PACKET_TCP, po);

   /* Find or create the correct session */
   tcp_create_ident(&ident, PACKET);
   if (session_get(&s, ident, TCP_IDENT_LEN) == -ENOTFOUND) {
      tcp_create_session(&s, PACKET);
      session_put(s);
   }

   /* Trace the sessions for injectors */
   SESSION_PASSTHRU(s, PACKET);
   
   /* Select right comunication way */
   direction = tcp_find_direction(s->ident, ident);
   SAFE_FREE(ident);
   
   /* Record last packet's seq */
   status = (struct tcp_status *)s->data;
   status->way[direction].last_seq = ntohl(tcp->seq) + PACKET->DATA.len;
   
   /* SYN counts as one byte */
   if ( tcp->flags & TH_SYN )
      status->way[direction].last_seq++;

   /* get the next decoder */
   next_decoder =  get_decoder(APP_LAYER, PL_DEFAULT);
   EXECUTE_DECODER(next_decoder);
   
   /* 
    * Modification checks and adjustments.
    * - tcp->seq and tcp->ack accoridng to injected/dropped bytes
    * - seq_adj according to PACKET->delta for modifications 
    *   or the whole payload for dropped packets.
    */   
   
   /* XXX [...] over TCP encapsulation not supported yet: 
    * upper layer may modify L3 structure
    */
   
   if (PACKET->flags & PO_DROPPED)
      status->way[direction].seq_adj -= PACKET->DATA.len;
   else if ((PACKET->flags & PO_MODIFIED) || 
            (status->way[direction].seq_adj != 0) || 
            (status->way[!direction].seq_adj != 0)) {
     
      /* adjust with the previously injected/dropped seq/ack */
      ORDER_ADD_LONG(tcp->seq, status->way[direction].seq_adj);
      ORDER_ADD_LONG(tcp->ack, -status->way[!direction].seq_adj);

      /* and now save the new delta */
      status->way[direction].seq_adj += PACKET->DATA.delta;

      /* adjust the len */
      PACKET->DATA.len += PACKET->DATA.delta;
            
      /* Recalculate checksum */
      tcp->csum = 0; 
      tcp->csum = L4_checksum(PACKET);
   }

   return NULL;
}

/*******************************************/

FUNC_INJECTOR(inject_tcp)
{
   struct session *s = NULL;
   void *ident = NULL;
   struct tcp_status *status;
   int direction;
   struct tcp_header *tcph;
   u_char *tcp_payload;
   u_int32 magic;
       
   /* Find the correct session */
   tcp_create_ident(&ident, PACKET);
   if (session_get(&s, ident, TCP_IDENT_LEN) == -ENOTFOUND) 
      return -ENOTFOUND;

   /* Rember where the payload has to start */
   tcp_payload = PACKET->packet;

   /* Allocate stack for tcp header */
   PACKET->packet -= sizeof(struct tcp_header);

   /* Create the tcp header */
   tcph = (struct tcp_header *)PACKET->packet;

   tcph->sport = PACKET->L4.src;
   tcph->dport = PACKET->L4.dst;
   tcph->x2    = 0;            
   tcph->off   = 5;            
   tcph->win   = htons(32120); 
   tcph->csum  = 0;            
   tcph->urp   = 0;            
   tcph->flags = TH_PSH;      
   
   /* Take the rest of the data from the sessions */
   status = (struct tcp_status *)s->data;
   direction = tcp_find_direction(s->ident, ident);
   tcph->seq = htonl(status->way[direction].last_seq + status->way[direction].seq_adj);
   
   /* Fake ACK seq (we didn't set the flag) */
   tcph->ack = htonl(status->way[!direction].last_seq + status->way[!direction].seq_adj);
   
   /* Prepare data for next injector */
   PACKET->session = s->prev_session;
   LENGTH += sizeof(struct tcp_header);     
   memcpy(&magic, s->prev_session->ident, 4);

   /* Go deeper into injectors chain */
   EXECUTE_INJECTOR(CHAIN_LINKED, magic);
      
   /* 
    * Attach the data (LENGTH was adjusted by LINKED injectors).
    * Set LENGTH to injectable data len.
    */
   LENGTH = GBL_IFACE->mtu - LENGTH;
   if (LENGTH > PACKET->inject_len)
      LENGTH = PACKET->inject_len;
   memcpy(tcp_payload, PACKET->inject, LENGTH);   
   
   /* Update inject counter into the session */
   status->way[direction].seq_adj += LENGTH;
   
   /* Calculate checksum */
   PACKET->L4.header = (u_char *)tcph;
   PACKET->L4.len = sizeof(struct tcp_header);
   PACKET->DATA.len = LENGTH; 
   tcph->csum = L4_checksum(PACKET);
      
   return ESUCCESS;
}

/*******************************************/

/* Sessions' stuff for tcp packets */


/*
 * create the ident for a session
 */

size_t tcp_create_ident(void **i, struct packet_object *po)
{
   struct tcp_ident *ident;

   /* allocate the ident for that session */
   SAFE_CALLOC(ident, 1, sizeof(struct tcp_ident));

   /* the magic */
   ident->magic = TCP_MAGIC;
      
   /* prepare the ident */
   memcpy(&ident->L3_src, &po->L3.src, sizeof(struct ip_addr));
   memcpy(&ident->L3_dst, &po->L3.dst, sizeof(struct ip_addr));

   ident->L4_src = po->L4.src;
   ident->L4_dst = po->L4.dst;

   /* return the ident */
   *i = ident;

   /* return the lenght of the ident */
   return sizeof(struct tcp_ident);
}


/*
 * compare two session ident
 *
 * return 1 if it matches
 */

int tcp_match(void *id_sess, void *id_curr)
{
   struct tcp_ident *ids = id_sess;
   struct tcp_ident *id = id_curr;

   /* sanity check */
   BUG_IF(ids == NULL);
   BUG_IF(id == NULL);
  
   /* 
    * is this ident from our level ?
    * check the magic !
    */
   if (ids->magic != id->magic)
      return 0;
   
   /* from source to dest */
   if (ids->L4_src == id->L4_src &&
       ids->L4_dst == id->L4_dst &&
       !ip_addr_cmp(&ids->L3_src, &id->L3_src) &&
       !ip_addr_cmp(&ids->L3_dst, &id->L3_dst) )
      return 1;
   
   /* from dest to source */
   if (ids->L4_src == id->L4_dst &&
       ids->L4_dst == id->L4_src &&
       !ip_addr_cmp(&ids->L3_src, &id->L3_dst) &&
       !ip_addr_cmp(&ids->L3_dst, &id->L3_src) )
      return 1;

   return 0;
}


/*
 * prepare the ident and the pointer to match function
 * for a dissector.
 */

void tcp_create_session(struct session **s, struct packet_object *po)
{
   void *ident;

   DEBUG_MSG("tcp_create_session");

   /* allocate the session */
   SAFE_CALLOC(*s, 1, sizeof(struct session));
   
   /* create the ident */
   (*s)->ident_len = tcp_create_ident(&ident, po);
   
   /* link to the session */
   (*s)->ident = ident;

   /* the matching function */
   (*s)->match = &tcp_match;

   /* alloca of data elements */
   SAFE_CALLOC((*s)->data, 1, sizeof(struct tcp_status));
}

/*
 * Find right comunication way for session data.
 * First array data is relative to the direction first caught.
 */ 
int tcp_find_direction(void *ids, void *id)
{
   if (memcmp(ids, id, TCP_IDENT_LEN)) 
      return 1;
      
   return 0;
} 

/* EOF */

// vim:ts=3:expandtab

