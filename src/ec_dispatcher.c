/*
    ettercap -- top half and dispatching module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_dispatcher.c,v 1.5 2003/03/14 23:46:36 alor Exp $
*/

#include <ec.h>
#include <ec_threads.h>

/* proto */

void top_half_queue_add(struct packet_object *po);
EC_THREAD_FUNC(top_half);

/*******************************************/

/*
 * top half function
 * it is the dispatcher for the various methods
 * which need to process packet objects 
 * created by the bottom_half (capture).
 * it read the queue created by top_half_queue_add()
 * and deliver the po to all the registered functions
 */

EC_THREAD_FUNC(top_half)
{
   DEBUG_MSG("top_half activated !");
  
   ec_thread_init();

   pthread_exit(0);
   
   /* XXX -- implement the read from list */
   while(1) sleep(1);
 
   /* HOOK_POINT: DISPATCHER */
   
}


void top_half_queue_add(struct packet_object *po)
{
   /* XXX -- implement the list */
   packet_print(po);
}


/* EOF */

// vim:ts=3:expandtab

