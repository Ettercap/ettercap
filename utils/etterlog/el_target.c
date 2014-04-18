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


void target_compile(char *target)
{
#define MAX_TOK 3
   char valid[] = "1234567890/.,-;:ABCDEFabcdef";
   char *tok[MAX_TOK];
   char *p;
   int i = 0;

   /* sanity check */ 
   if (strlen(target) != strspn(target, valid))
      FATAL_ERROR("TARGET contains invalid chars !");

   /* TARGET parsing */
   for(p=strsep(&target, "/"); p != NULL; p=strsep(&target, "/")) {
      tok[i++] = strdup(p);
      /* bad parsing */
      if (i > (MAX_TOK - 1)) break;
   }

   if (i != MAX_TOK)
      FATAL_ERROR("Incorrect number of token (//) in TARGET !!");

   /* reset the target */
   GBL_TARGET->all_mac = 0;
   GBL_TARGET->all_ip = 0;
   GBL_TARGET->all_port = 0;

   /* set the mac address */
   if (!strcmp(tok[0], ""))
      GBL_TARGET->all_mac = 1;
   else if (mac_addr_aton(tok[0], GBL_TARGET->mac) == 0)
      FATAL_ERROR("Incorrect TARGET MAC parsing... (%s)", tok[0]);

   /* parse the IP range */
   if (!strcmp(tok[1], ""))
      GBL_TARGET->all_ip = 1;
   else
      for(p=strsep(&tok[1], ";"); p != NULL; p=strsep(&tok[1], ";"))
         expand_range_ip(p, GBL_TARGET);

   /* 
    * expand the range into the port bitmap array
    * 1<<16 is MAX_PORTS 
    */
   if (!strcmp(tok[2], ""))
      GBL_TARGET->all_port = 1;
   else
      expand_token(tok[2], 1<<16, &add_port, GBL_TARGET->ports);

   /* free the data */
   for(i=0; i < MAX_TOK; i++)
      SAFE_FREE(tok[i]);
                        
}


/*
 * return true if the packet conform to TARGET
 */

int is_target_pck(struct log_header_packet *pck)
{
   int proto = 0;
   int good = 0;
   
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
    if (!GBL->reverse && proto == 0)
       return 0;
    
   /*
    * we have to check if the packet is complying with the filter
    * specified by the users.
    */
 
   /* it is in the source */
   if ( (GBL_TARGET->all_mac  || !memcmp(GBL_TARGET->mac, pck->L2_src, MEDIA_ADDR_LEN)) &&
        (GBL_TARGET->all_ip   || cmp_ip_list(&pck->L3_src, GBL_TARGET) ) &&
        (GBL_TARGET->all_port || BIT_TEST(GBL_TARGET->ports, ntohs(pck->L4_src))) )
      good = 1;

   /* it is in the dest */
   if ( (GBL_TARGET->all_mac  || !memcmp(GBL_TARGET->mac, pck->L2_dst, MEDIA_ADDR_LEN)) &&
        (GBL_TARGET->all_ip   || cmp_ip_list(&pck->L3_dst, GBL_TARGET)) &&
        (GBL_TARGET->all_port || BIT_TEST(GBL_TARGET->ports, ntohs(pck->L4_dst))) )
      good = 1;   
  
   /* check the reverse option */
   if (GBL->reverse ^ (good && proto) ) 
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
 
   /* it is in the source */
   if ( (GBL_TARGET->all_mac || !memcmp(GBL_TARGET->mac, hst->L2_addr, MEDIA_ADDR_LEN)) &&
        (GBL_TARGET->all_ip  || cmp_ip_list(&hst->L3_addr, GBL_TARGET) ) )
      host = 1;


   /* check the reverse option */
   if (GBL->reverse ^ (host && port) ) 
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

