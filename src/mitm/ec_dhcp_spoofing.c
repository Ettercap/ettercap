/*
    ettercap -- DHCP spoofing mitm module

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

    $Id: ec_dhcp_spoofing.c,v 1.4 2003/11/17 11:40:34 alor Exp $
*/

#include <ec.h>
#include <ec_mitm.h>
#include <ec_send.h>
#include <ec_sniff.h>
#include <ec_threads.h>
#include <ec_hook.h>
#include <ec_packet.h>
#include <ec_strings.h>

/* globals */

static struct target_env dhcp_ip_pool;
static struct ip_addr dhcp_netmask;
static struct ip_addr dhcp_dns;

/* protos */

void dhcp_spoofing_init(void);
static void dhcp_spoofing_start(char *args);
static void dhcp_spoofing_stop(void);
static void dhcp_spoofing(struct packet_object *po);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered mitm
 */

void __init dhcp_spoofing_init(void)
{
   struct mitm_method mm;

   mm.name = "dhcp";
   mm.start = &dhcp_spoofing_start;
   mm.stop = &dhcp_spoofing_stop;
   
   mitm_add(&mm);
}


/*
 * init the ICMP REDIRECT attack
 */
static void dhcp_spoofing_start(char *args)
{
   struct in_addr ipaddr;
   char *p;
   int i = 1;
  
   DEBUG_MSG("dhcp_spoofing_start");

   if (!strcmp(args, ""))
      FATAL_ERROR("DHCP spoofing needs a parameter.\n");
   
   /* check the parameter:
    *
    * ip_pool/netmask/dns
    */
   for (p = strsep(&args, "/"); p != NULL; p = strsep(&args, "/")) {
      /* first parameter (the ip_pool) */
      if (i == 1) {
         char tmp[strlen(p)+3];

         /* add the / to be able to use the target parsing function */
         sprintf(tmp, "/%s/", p);

         if (compile_target(tmp, &dhcp_ip_pool) != ESUCCESS)
            break;
         
      /* second parameter (the netmask) */
      } else if (i == 2) {
         /* convert from string */
         if (inet_aton(p, &ipaddr) == 0)
            break;
         /* get the netmask */
         ip_addr_init(&dhcp_netmask, AF_INET, (char *)&ipaddr);
         
      /* third parameter (the dns server) */
      } else if (i == 3) {
         char tmp[MAX_ASCII_ADDR_LEN];

         /* convert from string */
         if (inet_aton(p, &ipaddr) == 0)
            break;
         /* get the netmask */
         ip_addr_init(&dhcp_dns, AF_INET, (char *)&ipaddr);
         
         /* all the parameters were parsed correctly... */
         USER_MSG("DHCP spoofing: using specified ip_pool, netmask %s", ip_addr_ntoa(&dhcp_netmask, tmp));
         USER_MSG(", dns %s\n", ip_addr_ntoa(&dhcp_dns, tmp));
         /* add the hookpoint */
         hook_add(HOOK_PROTO_DHCP_REQ, dhcp_spoofing);
         return;
      }
      
      i++;
   }

   /* error parsing the parameter */
   FATAL_ERROR("DHCP spoofing: parameter number %d is incorrect.\n", i);
}


/*
 * shut down the redirect process
 */
static void dhcp_spoofing_stop(void)
{
   
   DEBUG_MSG("dhcp_spoofing_stop");
   
   USER_MSG("DHCP spoofing stopped.\n");
   
   /* remove the hookpoint */
   hook_del(HOOK_PROTO_DHCP_REQ, dhcp_spoofing);

}

/*
 * parses the request and send the spoofed reply
 */
static void dhcp_spoofing(struct packet_object *po)
{
   
}

/* EOF */

// vim:ts=3:expandtab

