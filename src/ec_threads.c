/*
    ettercap -- thread handling

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_threads.c,v 1.4 2003/03/20 16:25:23 alor Exp $
*/

#include <ec.h>
#include <ec_threads.h>

#include <pthread.h>

struct thread_list {
   struct ec_thread t;
   LIST_ENTRY (thread_list) next;
};


/* global data */

static LIST_HEAD(, thread_list) thread_list_head;

static pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;
#define THREADS_LOCK     do{ pthread_mutex_lock(&threads_mutex); } while(0)
#define THREADS_UNLOCK   do{ pthread_mutex_unlock(&threads_mutex); } while(0)
   
/* protos... */

char * ec_thread_getname(pthread_t id);
char * ec_thread_getdesc(pthread_t id);
void ec_thread_register(pthread_t id, char *name, char *desc);
pthread_t ec_thread_new(char *name, char *desc, void *(*function)(void *), void *args);
void ec_thread_destroy(pthread_t id);
void ec_thread_init(void);
void ec_thread_testcancel(void);
void ec_thread_kill_all(void);

/*******************************************/

/* returns the name of a thread */

char * ec_thread_getname(pthread_t id)
{
   struct thread_list *current;
   char *name;

   if (id == EC_SELF)
      id = pthread_self();

   LIST_FOREACH(current, &thread_list_head, next) {
      if (current->t.id == id) {
         name = current->t.name;
         THREADS_UNLOCK;
         return name;
      }
   }

   THREADS_UNLOCK;

   return "NR_THREAD";
}

/* returns the description of a thread */

char * ec_thread_getdesc(pthread_t id)
{
   struct thread_list *current;
   char *desc;

   if (id == EC_SELF)
      id = pthread_self();
  
   THREADS_LOCK;
   
   LIST_FOREACH(current, &thread_list_head, next) {
      if (current->t.id == id) {
         desc = current->t.description;
         THREADS_UNLOCK;
         return desc;
      }
   }
   
   THREADS_UNLOCK;
   
   return "";
}


/* add a thread in the thread list */

void ec_thread_register(pthread_t id, char *name, char *desc)
{
   struct thread_list *current, *newelem;

   if (id == EC_SELF)
      id = pthread_self();
   
   DEBUG_MSG("ec_thread_register -- [%d] %s", id, name);

   newelem = (struct thread_list *) calloc(1, sizeof(struct thread_list));
   ON_ERROR(newelem, NULL, "cant allocate memory");
              
   newelem->t.id = id;
   newelem->t.name = strdup(name);
   newelem->t.description = strdup(desc);

   THREADS_LOCK;
   
   LIST_FOREACH(current, &thread_list_head, next) {
      if (current->t.id == id) {
         SAFE_FREE(current->t.name);
         SAFE_FREE(current->t.description);
         LIST_REPLACE(current, newelem, next);
         SAFE_FREE(current);
         THREADS_UNLOCK;
         return;
      }
   }

   LIST_INSERT_HEAD(&thread_list_head, newelem, next);
   
   THREADS_UNLOCK;
   
}

/*
 * creates a new thread on the given function
 */

pthread_t ec_thread_new(char *name, char *desc, void *(*function)(void *), void *args)
{
   pthread_t id;

   DEBUG_MSG("ec_thread_new -- %s", name);

   if (pthread_create(&id, NULL, function, args) < 0)
      ERROR_MSG("not enough system resources to create a new thread");

   ec_thread_register(id, name, desc);

   DEBUG_MSG("ec_thread_new -- %d created ", (u_int32)id);
   
   return id;
}

/*
 * destroy a thread in the list
 */

void ec_thread_destroy(pthread_t id)
{
   struct thread_list *current;

   DEBUG_MSG("ec_thread_destroy -- terminating %lu [%s]", id, ec_thread_getname(id));

   pthread_cancel((pthread_t)id);

   pthread_join((pthread_t)id, NULL);

   THREADS_LOCK;
   
   LIST_FOREACH(current, &thread_list_head, next) {
      if (current->t.id == id) {
         SAFE_FREE(current->t.name);
         SAFE_FREE(current->t.description);
         LIST_REMOVE(current, next);
         SAFE_FREE(current);
         THREADS_UNLOCK;
         return;
      }
   }

   THREADS_UNLOCK;

}

/* 
 * set the state of a thread 
 * all the new thread should call this on startup
 */

void ec_thread_init(void)
{
   DEBUG_MSG("ec_thread_init -- %d", pthread_self());
   
   /* 
    * allow a thread to be cancelled as soon as the
    * cancellation  request  is received
    */
        
   pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

}

/*
 * kill all the registerd thread but
 * the calling one
 */

void ec_thread_kill_all(void)
{
   struct thread_list *current;
   pthread_t id = pthread_self();

   DEBUG_MSG("ec_thread_kill_all -- caller %lu [%s]", id, ec_thread_getname(id));

   LIST_FOREACH(current, &thread_list_head, next) {
      if (current->t.id != id) {
         ec_thread_destroy(current->t.id);      
      }
   }

}

/*
 * set a cancellation point
 */

void ec_thread_testcancel(void)
{
   pthread_testcancel();
}


/* EOF */

// vim:ts=3:expandtab

