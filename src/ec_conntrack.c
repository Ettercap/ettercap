/*
    ettercap -- connection list handling module

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

    $Id: ec_conntrack.c,v 1.1 2003/07/18 21:36:45 alor Exp $
*/

#include <ec.h>
#include <ec_threads.h>
#include <ec_packet.h>
#include <ec_hook.h>

/* protos */

void __init conntrack_init(void);

static void conntrack_parse(struct packet_object *po);

/************************************************/
  
/*
 * add the hook function
 */
void __init conntrack_init(void)
{
   /* receive all the top half packets */
   hook_add(HOOK_DISPATCHER, &conntrack_parse);
}

/*
 * the conntrack main()
 */
static void conntrack_parse(struct packet_object *po)
{
   //USER_MSG("TRACKED\n");

#if 0
   conn = conn_search(po);

   if (conn)
      conn_update(conn, po);
   else
      conn_add(po);
   
#endif
}

/* EOF */

// vim:ts=3:expandtab

