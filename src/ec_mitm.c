/*
    ettercap -- mitm management module

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

    $Id: ec_mitm.c,v 1.3 2003/09/18 22:15:03 alor Exp $
*/

#include <ec.h>
#include <ec_mitm.h>

/* globals */


static SLIST_HEAD (, mitm_entry) mitm_table;

struct mitm_entry {
   int selected;
   int started;
   struct mitm_method *mm;
   SLIST_ENTRY (mitm_entry) next;
};


/* protos */

void mitm_add(struct mitm_method *mm);
int mitm_set(u_char *name);
void mitm_start(void);
void mitm_stop(void);

/*******************************************/

/*
 * register a new mitm method in the table 
 */
void mitm_add(struct mitm_method *mm)
{
   struct mitm_entry *e;

   e = calloc(1, sizeof(struct mitm_entry));
   ON_ERROR(e, NULL, "Can't allocate memory");

   /* copy the mm struct */
   e->mm = calloc(1, sizeof(struct mitm_method));
   ON_ERROR(e->mm, NULL, "Can't allocate memory");

   memcpy(e->mm, mm, sizeof(struct mitm_method));
   
   SLIST_INSERT_HEAD(&mitm_table, e, next);
   
}


/*
 * set the 'selected' flag in the table
 * used by ec_parse.c
 */
int mitm_set(u_char *name)
{
   struct mitm_entry *e;

   DEBUG_MSG("mitm_set: %s", name);
   
   /* search the name and set it */
   SLIST_FOREACH(e, &mitm_table, next) {
      if (!strcasecmp(e->mm->name, name)) {
         e->selected = 1;
         return ESUCCESS;
      }
   }

   return -ENOTFOUND;
}


/* 
 * starts all the method with the selected flag set.
 * it is possible to start multiple method simultaneusly
 */
void mitm_start(void)
{
   struct mitm_entry *e;

   DEBUG_MSG("mitm_start");
   
   /* start all the selected methods */
   SLIST_FOREACH(e, &mitm_table, next) {
      if (e->selected) {
         DEBUG_MSG("mitm_start: starting %s", e->mm->name);
         e->mm->start();
         e->started = 1;
      }
   }
}


/*
 * stop all the previously started method
 */
void mitm_stop(void)
{
   struct mitm_entry *e;

   DEBUG_MSG("mitm_stop");
   
   /* stop all the started methods */
   SLIST_FOREACH(e, &mitm_table, next) {
      if (e->started) {
         DEBUG_MSG("mitm_stop: stopping %s", e->mm->name);
         e->mm->stop();
      }
   }
   
}

/* EOF */

// vim:ts=3:expandtab

