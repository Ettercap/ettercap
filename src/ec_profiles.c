/*
    ettercap -- host profiling module

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

    $Id: ec_profiles.c,v 1.6 2003/06/10 10:39:37 alor Exp $
*/

#include <ec.h>
#include <ec_passive.h>
#include <ec_profiles.h>
#include <ec_packet.h>
#include <ec_hook.h>

/* globals */

/* protos */

void __init profiles_init(void);
void profile_parse(struct packet_object *po);
int profile_add(struct packet_object *po);

/************************************************/
  
/*
 * add the hook function
 */
void __init profiles_init(void)
{
   /* XXX -- add other hook for ICMP and so on.. */
         
   /* add the hook for the ARP packets */
   hook_add(PACKET_ARP, &profile_parse);
         
   /* receive all the top half packets */
   hook_add(HOOK_DISPATCHER, &profile_parse);
}


/*
 * decides if the packet has to be added
 * to the profiles
 */
void profile_parse(struct packet_object *po)
{
   /*
    * call the add function only if the packet
    * is interesting...
    * we don't want to log conversations, only
    * open ports, user and pass... ;)
    */
   if ( po->L3.proto == htons(LL_TYPE_ARP) ||               /* arp packets */
        (is_open_src_port(po) || is_open_dst_port(po)) ||   /* the port is open */
        strcmp(po->PASSIVE.fingerprint, "") ||              /* collected fingerprint */  
        po->DISSECTOR.user ||                               /* user */
        po->DISSECTOR.pass ||                               /* pass */
        po->DISSECTOR.info ||                               /* info */
        po->DISSECTOR.banner                                /* banner */
      )
      profile_add(po);
      
   return;
}


/* 
 * add the infos to the profiles tables
 */
int profile_add(struct packet_object *po)
{
return 0;
   printf("[%s] [%s] [%s] [%s] [%s]\n", po->PASSIVE.fingerprint,
         po->DISSECTOR.user, po->DISSECTOR.pass,
         po->DISSECTOR.info, po->DISSECTOR.banner);
   return 0;   
}


/* EOF */

// vim:ts=3:expandtab

