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

    $Id: ec_dhcp_spoofing.c,v 1.1 2003/11/11 17:17:53 alor Exp $
*/

#include <ec.h>
#include <ec_mitm.h>
#include <ec_send.h>
#include <ec_sniff.h>
#include <ec_threads.h>
#include <ec_hook.h>
#include <ec_packet.h>

/* globals */


/* protos */

void dhcp_spoofing_init(void);
static void dhcp_spoofing_start(char *args);
static void dhcp_spoofing_stop(void);

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
  
   DEBUG_MSG("dhcp_spoofing_start");

   /* check the parameter */
   if (!strcmp(args, "")) {
      USER_MSG("FATAL: DHCP spoofing needs a parameter.\n");
      return;
   } else {
   }

}


/*
 * shut down the redirect process
 */
static void dhcp_spoofing_stop(void)
{
   
   DEBUG_MSG("dhcp_spoofing_stop");
   
   USER_MSG("DHCP spoofing stopped.\n");

}


/* EOF */

// vim:ts=3:expandtab

