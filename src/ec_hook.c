/*
    ettercap -- hook points handling

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_hook.c,v 1.2 2003/03/22 15:41:22 alor Exp $
*/

#include <ec.h>
#include <ec_hook.h>
#include <ec_packet.h>

#include <pthread.h>

struct hook_list {
   int point;
   void (*func)(struct packet_object *po);
   LIST_ENTRY (hook_list) next;
};

/* global data */

static LIST_HEAD(, hook_list) hook_list_head;

pthread_mutex_t hook_mutex = PTHREAD_MUTEX_INITIALIZER;
#define HOOK_LOCK     do{ pthread_mutex_lock(&hook_mutex); } while(0)
#define HOOK_UNLOCK   do{ pthread_mutex_unlock(&hook_mutex); } while(0)
   
/* protos... */

void hook_point(int point, struct packet_object *po);
void hook_add(int point, void (*func)(struct packet_object *po) );
int hook_del(int point, void (*func)(struct packet_object *po) );

/*******************************************/

/* execute the functions registered in that hook point */

void hook_point(int point, struct packet_object *po)
{
   struct hook_list *current;

   HOOK_LOCK;
   
   LIST_FOREACH(current, &hook_list_head, next) 
      if (current->point == point)
         current->func(po);
   
   HOOK_UNLOCK;
   
   return;
}


/* add a function to an hook point */

void hook_add(int point, void (*func)(struct packet_object *po) )
{
   struct hook_list *newelem;

   newelem = (struct hook_list *) calloc(1, sizeof(struct hook_list));
   ON_ERROR(newelem, NULL, "cant allocate memory");
              
   newelem->point = point;
   newelem->func = func;

   HOOK_LOCK;
   
   LIST_INSERT_HEAD(&hook_list_head, newelem, next);
   
   HOOK_UNLOCK;
   
}

/* remove a function from an hook point */

int hook_del(int point, void (*func)(struct packet_object *po) )
{
   struct hook_list *current;

   DEBUG_MSG("hook_del -- %d [%p]", point, func);

   HOOK_LOCK;
   
   LIST_FOREACH(current, &hook_list_head, next) {
      if (current->point == point && current->func == func) {
         LIST_REMOVE(current, next);
         SAFE_FREE(current);
         HOOK_UNLOCK;
         return ESUCCESS;
      }
   }

   HOOK_UNLOCK;

   return -ENOTFOUND;
}


/* EOF */

// vim:ts=3:expandtab

