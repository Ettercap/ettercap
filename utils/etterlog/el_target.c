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

#ifdef WITH_IPV6
/* Adds IPv6 address to the target list */
static int expand_ipv6(char *str, struct target_env *target)
{
   struct ip_addr ip;

   if(ip_addr_pton(str, &ip) != ESUCCESS)
      ui_error("Invalid IPv6 address");

   add_ip_list(&ip, target);
   return ESUCCESS;
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
      ui_fatal_error("TARGET (%s) contains invalid chars !", string);

   /* TARGET parsing */
   for (p = strsep(&string, "/"); p != NULL; p = strsep(&string, "/")) {
      tok[i++] = strdup(p);
      /* bad parsing */
      if (i > (MAX_TOK - 1)) break;
   }

   if (i != MAX_TOK)
#ifdef WITH_IPV6
      ui_fatal_error("Incorrect number of token (///) in TARGET !!");
#else
      ui_fatal_error("Incorrect number of token (//) in TARGET !!");
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
      ui_fatal_error("Incorrect TARGET MAC parsing... (%s)", tok[MAC_TOK]);

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
      if (expand_token(tok[PORT_TOK], 1<<16, &add_port, target->ports) == -EFATAL)
         ui_fatal_error("Invalid port range");
   }

   for(i = 0; i < MAX_TOK; i++)
      SAFE_FREE(tok[i]);

   return ESUCCESS;
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

    if (!GBL_TARGET->proto || !strcasecmp(GBL_TARGET->proto, "all"))  
       proto = 1;

    if (GBL_TARGET->proto && !strcasecmp(GBL_TARGET->proto, "tcp") 
          && pck->L4_proto == NL_TYPE_TCP)
       proto = 1;
   
    if (GBL_TARGET->proto && !strcasecmp(GBL_TARGET->proto, "udp") 
          && pck->L4_proto == NL_TYPE_UDP)
       proto = 1;
    
    /* the protocol does not match */
    if (!GBL_OPTIONS->reverse && proto == 0)
       return 0;
    
   /*
    * we have to check if the packet is complying with the filter
    * specified by the users.
    */

   /* determine the address family of the current host */
   switch (ntohs(pck->L3_src.addr_type)) {
      case AF_INET:
         all_ips = GBL_TARGET->all_ip;
         break;
      case AF_INET6:
         all_ips = GBL_TARGET->all_ip6;
         break;
      default:
         all_ips = 1;
   }
 
   /* it is in the source */
   if ( (GBL_TARGET->all_mac  || !memcmp(GBL_TARGET->mac, pck->L2_src, MEDIA_ADDR_LEN)) &&
        (            all_ips  || cmp_ip_list(&pck->L3_src, GBL_TARGET) ) &&
        (GBL_TARGET->all_port || BIT_TEST(GBL_TARGET->ports, ntohs(pck->L4_src))) )
      good = 1;

   /* it is in the dest - we can assume the address family is the same as in src */
   if ( (GBL_TARGET->all_mac  || !memcmp(GBL_TARGET->mac, pck->L2_dst, MEDIA_ADDR_LEN)) &&
        (            all_ips  || cmp_ip_list(&pck->L3_dst, GBL_TARGET)) &&
        (GBL_TARGET->all_port || BIT_TEST(GBL_TARGET->ports, ntohs(pck->L4_dst))) )
      good = 1;   
  
   /* check the reverse option */
   if (GBL_OPTIONS->reverse ^ (good && proto) ) 
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

   if (!GBL_TARGET->proto || !strcasecmp(GBL_TARGET->proto, "all"))  
      proto = 1;
   
   /* all the ports are good */
   if (GBL_TARGET->all_port && proto)
      port = 1;
   else {
      LIST_FOREACH(o, &(hst->open_ports_head), next) {
    
         if (GBL_TARGET->proto && !strcasecmp(GBL_TARGET->proto, "tcp") 
             && o->L4_proto == NL_TYPE_TCP)
            proto = 1;
   
         if (GBL_TARGET->proto && !strcasecmp(GBL_TARGET->proto, "udp") 
             && o->L4_proto == NL_TYPE_UDP)
            proto = 1;

         /* if the port is open, it matches */
         if (proto && (GBL_TARGET->all_port || BIT_TEST(GBL_TARGET->ports, ntohs(o->L4_addr))) ) {
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
         all_ips = GBL_TARGET->all_ip;
         break;
      case AF_INET6:
         all_ips = GBL_TARGET->all_ip6;
         break;
      default:
         all_ips = 1;
   }

   /* check if current host matches the filter */
   if ( (GBL_TARGET->all_mac || !memcmp(GBL_TARGET->mac, hst->L2_addr, MEDIA_ADDR_LEN)) &&
        (all_ips  || cmp_ip_list(&hst->L3_addr, GBL_TARGET) ) )
      host = 1;


   /* check the reverse option */
   if (GBL_OPTIONS->reverse ^ (host && port) ) 
      return 1;
   else
      return 0;

}


/* 
 * return ESUCCESS if the user 'user' is in the user list
 */

int find_user(struct host_profile *hst, char *user)
{
   struct open_port *o;
   struct active_user *u;
      
   if (user == NULL)
      return ESUCCESS;
   
   LIST_FOREACH(o, &(hst->open_ports_head), next) {
      LIST_FOREACH(u, &(o->users_list_head), next) {
         if (strcasestr(u->user, user))
            return ESUCCESS;
      }
   }
   
   return -ENOTFOUND;
}




/* EOF */

// vim:ts=3:expandtab

