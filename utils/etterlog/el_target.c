/*
    etterlog -- target filtering module

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

#include <el.h>
#include <el_functions.h>

/*******************************************/

// we cannot use the libettercap functions, since theu use I/O functions, that in order
// to work needs to drag in the ec_ui functions.

static void add_port(void *ports, u_int n);
static void add_ip(void *digit, u_int n);
static int expand_range_ip(char *str, void *target);

#ifdef WITH_IPV6
/* Adds IPv6 address to the target list */
static int expand_ipv6(char *str, struct target_env *target)
{
   struct ip_addr ip;

   if(ip_addr_pton(str, &ip) != E_SUCCESS)
      ui_error("Invalid IPv6 address");

   add_ip_list(&ip, target);
   return E_SUCCESS;
}
#endif

/*
 * convert a string into a target env
 */
int compile_target(char *string, struct target_env *target)
{

#define MAC_TOK 0
#define IP_TOK 1

#ifdef WITH_IPV6
#define IPV6_TOK 2
#define PORT_TOK 3
#define MAX_TOK 4
#else
#define PORT_TOK 2
#define MAX_TOK 3
#endif

   char valid[] = "1234567890/.,-;:ABCDEFabcdef";
   char *tok[MAX_TOK];
   char *p;
   int i = 0;

//   DEBUG_MSG("compile_target TARGET: %s", string);

   /* reset the special marker */
   target->all_mac = 0;
   target->all_ip = 0;
   target->all_ip6 = 0;
   target->all_port = 0;
   /* check for invalid char */
   if (strlen(string) != strspn(string, valid))
      FATAL_ERROR("TARGET (%s) contains invalid chars !", string);

   /* TARGET parsing */
   for (p = strsep(&string, "/"); p != NULL; p = strsep(&string, "/")) {
      tok[i++] = strdup(p);
      /* bad parsing */
      if (i > (MAX_TOK - 1)) break;
   }

   if (i != MAX_TOK)
#ifdef WITH_IPV6
      FATAL_ERROR("Incorrect number of token (///) in TARGET !!");
#else
      FATAL_ERROR("Incorrect number of token (//) in TARGET !!");
#endif

//   DEBUG_MSG("MAC  : [%s]", tok[MAC_TOK]);
//   DEBUG_MSG("IP   : [%s]", tok[IP_TOK]);
//#ifdef WITH_IPV6
//   DEBUG_MSG("IPv6 : [%s]", tok[IPV6_TOK]);
//#endif
//   DEBUG_MSG("PORT : [%s]", tok[PORT_TOK]);

   /* set the mac address */
   if (!strcmp(tok[MAC_TOK], ""))
      target->all_mac = 1;
   else if (mac_addr_aton(tok[MAC_TOK], target->mac) == 0)
      FATAL_ERROR("Incorrect TARGET MAC parsing... (%s)", tok[MAC_TOK]);

   /* parse the IP range */
   if (!strcmp(tok[IP_TOK], ""))
      target->all_ip = 1;
   else
     for(p = strsep(&tok[IP_TOK], ";"); p != NULL; p = strsep(&tok[IP_TOK], ";"))
        expand_range_ip(p, target);

#ifdef WITH_IPV6 
   if(!strcmp(tok[IPV6_TOK], ""))
      target->all_ip6 = 1;
   else
      for(p = strsep(&tok[IPV6_TOK], ";"); p != NULL; p = strsep(&tok[IPV6_TOK], ";"))
         expand_ipv6(p, target);
#endif

   /* 
    * if only one of IP address families is specified,
    * the other is not automatically treated as ANY
    * because that is not the natural behaviour of a filter
    */
   if (!target->all_ip || !target->all_ip6) {
      /* one of the IP target was specified, reset the ANY state */
      target->all_ip = 0;
      target->all_ip6 = 0;
   }

   /* 
    * expand the range into the port bitmap array
    * 1<<16 is MAX_PORTS 
    */
   if (!strcmp(tok[PORT_TOK], ""))
      target->all_port = 1;
   else {
      if (expand_token(tok[PORT_TOK], 1<<16, &add_port, target->ports) == -E_FATAL)
         FATAL_ERROR("Invalid port range");
   }

   for(i = 0; i < MAX_TOK; i++)
      SAFE_FREE(tok[i]);

   return E_SUCCESS;
}

/*
 * set the bit of the relative port 
 */
static void add_port(void *ports, u_int n)
{
   u_int8 *bitmap = ports;

     if (n > 1<<16)
      FATAL_ERROR("Port outside the range (65535) !!");

   BIT_SET(bitmap, n);
}

/*
 * this structure is used to contain all the possible
 * value of a token.
 * it is used as a digital clock.
 * an impulse is made to the last digit and it increment
 * its value, when it reach the maximum, it reset itself 
 * and gives an impulse to the second to last digit.
 * the impulse is propagated till the first digit so all
 * the values are displayed as in a daytime from 00:00 to 23:59
 */

struct digit {
   int n;
   int cur;
   u_char values[0xff];
};

/* 
 * prepare the set of 4 digit to create an IP address
 */

static int expand_range_ip(char *str, void *target)
{
   struct digit ADDR[4];
   struct ip_addr tmp;
   struct in_addr ipaddr;
   char *addr[4];
   char parsed_ip[16];
   char *p, *q;
   int i = 0, j;
   int permut = 1;
   char *tok;

   memset(&ADDR, 0, sizeof(ADDR));

   p = str;

   /* tokenize the ip into 4 slices */
   while ((q = ec_strtok(p, ".", &tok)) ) {
      addr[i++] = strdup(q);
      /* reset p for the next strtok */
      if (p != NULL) p = NULL;
      if (i > 3) break;
   }

   if (i != 4)
      FATAL_ERROR("Invalid IP format !!");

   DEBUG_MSG("expand_range_ip -- [%s] [%s] [%s] [%s]", addr[0], addr[1], addr[2], addr[3]);

   for (i = 0; i < 4; i++) {
      p = addr[i];
      if (expand_token(addr[i], 255, &add_ip, &ADDR[i]) == -E_FATAL)
         FATAL_ERROR("Invalid port range");
   }

   /* count the free permutations */
   for (i = 0; i < 4; i++)
      permut *= ADDR[i].n;

   /* give the impulses to the last digit */
   for (i = 0; i < permut; i++) {

      snprintf(parsed_ip, 16, "%d.%d.%d.%d",  ADDR[0].values[ADDR[0].cur],
                                         ADDR[1].values[ADDR[1].cur],
                                         ADDR[2].values[ADDR[2].cur],
                                         ADDR[3].values[ADDR[3].cur]);

      if (inet_pton(AF_INET, parsed_ip, &ipaddr) == 0)
         FATAL_ERROR("Invalid IP address (%s)", parsed_ip);

      ip_addr_init(&tmp, AF_INET,(u_char *)&ipaddr );
      add_ip_list(&tmp, target);

      /* give the impulse to the last octet */
      ADDR[3].cur++;

      /* adjust the other digits as in a digital clock */
      for (j = 2; j >= 0; j--) {
         if ( ADDR[j+1].cur >= ADDR[j+1].n  ) {
            ADDR[j].cur++;
            ADDR[j+1].cur = 0;
         }
      }
   }

   for (i = 0; i < 4; i++)
      SAFE_FREE(addr[i]);

   return E_SUCCESS;
}

/* fill the digit structure with data */
static void add_ip(void *digit, u_int n)
{
   struct digit *buf = digit;

   buf->n++;
   buf->values[buf->n - 1] = (u_char) n;
}

/*
 * return true if the packet conform to TARGET
 */

int is_target_pck(struct log_header_packet *pck)
{
   int proto = 0;
   int good = 0;
   int all_ips = 0;
   
   /* 
    * first check the protocol.
    * if it is not the one specified it is 
    * useless to parse the mac, ip and port
    */

    if (!EL_GBL_TARGET->proto || !strcmp(EL_GBL_TARGET->proto, "") || !strcasecmp(EL_GBL_TARGET->proto, "all"))  
       proto = 1;

    if (EL_GBL_TARGET->proto && !strcasecmp(EL_GBL_TARGET->proto, "tcp") 
          && pck->L4_proto == NL_TYPE_TCP)
       proto = 1;
   
    if (EL_GBL_TARGET->proto && !strcasecmp(EL_GBL_TARGET->proto, "udp") 
          && pck->L4_proto == NL_TYPE_UDP)
       proto = 1;
    
    /* the protocol does not match */
    if (!EL_GBL_OPTIONS->reverse && proto == 0)
       return 0;
    
   /*
    * we have to check if the packet is complying with the filter
    * specified by the users.
    */

   /* determine the address family of the current host */
   switch (ntohs(pck->L3_src.addr_type)) {
      case AF_INET:
         all_ips = EL_GBL_TARGET->all_ip;
         break;
      case AF_INET6:
         all_ips = EL_GBL_TARGET->all_ip6;
         break;
      default:
         all_ips = 1;
   }
 
   /* it is in the source */
   if ( (EL_GBL_TARGET->all_mac  || !memcmp(EL_GBL_TARGET->mac, pck->L2_src, MEDIA_ADDR_LEN)) &&
        (            all_ips  || cmp_ip_list(&pck->L3_src, EL_GBL_TARGET) ) &&
        (EL_GBL_TARGET->all_port || BIT_TEST(EL_GBL_TARGET->ports, ntohs(pck->L4_src))) )
      good = 1;

   /* it is in the dest - we can assume the address family is the same as in src */
   if ( (EL_GBL_TARGET->all_mac  || !memcmp(EL_GBL_TARGET->mac, pck->L2_dst, MEDIA_ADDR_LEN)) &&
        (            all_ips  || cmp_ip_list(&pck->L3_dst, EL_GBL_TARGET)) &&
        (EL_GBL_TARGET->all_port || BIT_TEST(EL_GBL_TARGET->ports, ntohs(pck->L4_dst))) )
      good = 1;   
  
   /* check the reverse option */
   if (EL_GBL_OPTIONS->reverse ^ (good && proto) ) 
      return 1;
      
   
   return 0;
}

/*
 * return 1 if the packet conform to TARGET
 */

int is_target_info(struct host_profile *hst)
{
   struct open_port *o;
   int proto = 0;
   int port = 0;
   int host = 0;
   int all_ips = 0;
   
   /* 
    * first check the protocol.
    * if it is not the one specified it is 
    * useless to parse the mac, ip and port
    */

   if (!EL_GBL_TARGET->proto || !strcmp(EL_GBL_TARGET->proto, "") || !strcasecmp(EL_GBL_TARGET->proto, "all"))  
      proto = 1;
   
   /* all the ports are good */
   if (EL_GBL_TARGET->all_port && proto)
      port = 1;
   else {
      LIST_FOREACH(o, &(hst->open_ports_head), next) {
    
         if (EL_GBL_TARGET->proto && !strcasecmp(EL_GBL_TARGET->proto, "tcp") 
             && o->L4_proto == NL_TYPE_TCP)
            proto = 1;
   
         if (EL_GBL_TARGET->proto && !strcasecmp(EL_GBL_TARGET->proto, "udp") 
             && o->L4_proto == NL_TYPE_UDP)
            proto = 1;

         /* if the port is open, it matches */
         if (proto && (EL_GBL_TARGET->all_port || BIT_TEST(EL_GBL_TARGET->ports, ntohs(o->L4_addr))) ) {
            port = 1;
            break;
         }
      }
   }

   /*
    * we have to check if the packet is complying with the filter
    * specified by the users.
    */
 
   /* determine the address family of the current host */
   switch (ntohs(hst->L3_addr.addr_type)) {
      case AF_INET:
         all_ips = EL_GBL_TARGET->all_ip;
         break;
      case AF_INET6:
         all_ips = EL_GBL_TARGET->all_ip6;
         break;
      default:
         all_ips = 1;
   }

   /* check if current host matches the filter */
   if ( (EL_GBL_TARGET->all_mac || !memcmp(EL_GBL_TARGET->mac, hst->L2_addr, MEDIA_ADDR_LEN)) &&
        (all_ips  || cmp_ip_list(&hst->L3_addr, EL_GBL_TARGET) ) )
      host = 1;


   /* check the reverse option */
   if (EL_GBL_OPTIONS->reverse ^ (host && port) ) 
      return 1;
   else
      return 0;

}


/* 
 * return E_SUCCESS if the user 'user' is in the user list
 */

int find_user(struct host_profile *hst, char *user)
{
   struct open_port *o;
   struct active_user *u;
      
   if (user == NULL)
      return E_SUCCESS;
   
   LIST_FOREACH(o, &(hst->open_ports_head), next) {
      LIST_FOREACH(u, &(o->users_list_head), next) {
         if (strcasestr(u->user, user))
            return E_SUCCESS;
      }
   }
   
   return -E_NOTFOUND;
}




/* EOF */

// vim:ts=3:expandtab

