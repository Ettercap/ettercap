/*
    ettercap -- ARP poisoning mitm module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/mitm/ec_arp_poisoning.c,v 1.1 2003/08/18 21:25:16 alor Exp $
*/

#include <ec.h>
#include <ec_mitm.h>


/* protos */

void arp_poisoning_init(void);
static void arp_poisoning_start(void);
static void arp_poisoning_stop(void);

/*******************************************/

/*
 * this function is the initializer.
 * it adds the entry in the table of registered mitm
 */

void __init arp_poisoning_init(void)
{
   struct mitm_method mm;

   mm.name = "arp";
   mm.start = &arp_poisoning_start;
   mm.stop = &arp_poisoning_stop;
   
   mitm_add(&mm);
}

/*
 * init the ARP POISONING attack
 */
static void arp_poisoning_start(void)
{
   NOT_IMPLEMENTED();
}


/*
 * shut down the poisoning process
 */
static void arp_poisoning_stop(void)
{
   NOT_IMPLEMENTED();
}

/* EOF */

// vim:ts=3:expandtab

