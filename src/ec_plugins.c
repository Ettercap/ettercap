/*
    ettercap -- plugin handling

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_plugins.c,v 1.9 2003/05/19 10:58:53 alor Exp $
*/

#include <ec.h>
#include <ec_plugins.h>
#include <ec_parser.h>

#include <dirent.h>

#ifndef HAVE_SCANDIR
   #include <missing/scandir.h>
#endif

//#include <ltdl.h>
#ifdef HAVE_DLFCN_H
   #include <dlfcn.h>
#endif

/* symbol prefix for some OSes */
#ifdef NEED_USCORE
   #define SYM_PREFIX "_"
#else
   #define SYM_PREFIX ""
#endif
         

/* global data */

struct plugin_entry {
   void *handle;
   char activated;   /* if the init fuction was already called */
   struct plugin_ops *ops;
   SLIST_ENTRY(plugin_entry) next;
};

static SLIST_HEAD(, plugin_entry) plugin_head;

/* protos... */

void plugin_load_all(void);
void plugin_unload_all(void);
int plugin_load_single(char *path, char *name);
int plugin_register(void *handle, struct plugin_ops *ops);
int plugin_init(char *name);
int plugin_fini(char *name);
int plugin_list_print(int min, int max, void (*func)(char, struct plugin_ops *));
int plugin_get_type(char *name);
int plugin_is_activated(char *name);

/*******************************************/

/* 
 * load a plugin given the full path
 */

int plugin_load_single(char *path, char *name)
{
#ifdef HAVE_PLUGINS
   char file[strlen(path)+strlen(name)+1];
   void *handle;
   int (*plugin_load)(void *);
   
   snprintf(file, sizeof(file), "%s%s", path, name);
  
   DEBUG_MSG("plugin_load: %s", file);
   
   /* load the plugin */
   handle = dlopen(file, RTLD_NOW);

   if (handle == NULL) {
      DEBUG_MSG("plugin_load_single - %s - dlopen() | %s", file, dlerror());
      return -EINVALID;
   }
   
   /* find the loading function */
   plugin_load = dlsym(handle, SYM_PREFIX "plugin_load");
   
   if (plugin_load == NULL) {
      DEBUG_MSG("plugin_load_single - %s - dlsym() | %s", file, dlerror());
      dlclose(handle);
      return -EINVALID;
   }

   /* 
    * return the same value of plugin_register 
    * we pass the handle to the plugin, which
    * int turn passes it to the plugin_register 
    * function
    */
   return plugin_load(handle);
#else
   FATAL_MSG("Plugin support was disabled by configure...");
   return -EINVALID;
#endif
}


/*
 * search and load all plugins in INSTALL_PREFIX/lib
 */

void plugin_load_all(void)
{
   struct dirent **namelist;
   int n, i, ret;
   int t = 0;
   
   DEBUG_MSG("plugin_loadall");

//   if (lt_dlinit() != 0)
//      ERROR_MSG("lt_dlinit()");

   /* XXX - replace "." with INSTALL_PREFIX"/lib/" */

   n = scandir(".", &namelist, 0, alphasort);
  
   for(i = n-1; i >= 0; i--) {
      if ( match_pattern(namelist[i]->d_name, PLUGIN_PATTERN) ) {
         ret = plugin_load_single("./", namelist[i]->d_name);
         switch (ret) {
            case ESUCCESS:
               t++;
               break;
            case -EVERSION:
               USER_MSG("plugin %s was compiled for a different ettercap version...\n", namelist[i]->d_name);
               DEBUG_MSG("plugin %s was compiled for a different ettercap version...", namelist[i]->d_name);
               break;
            case -EINVALID:
            default:
               USER_MSG("plugin %s cannot be loaded...\n", namelist[i]->d_name);
               DEBUG_MSG("plugin %s cannot be loaded...", namelist[i]->d_name);
               break;
         }
      }
   }
   
   USER_MSG("%4d plugins loaded\n", t);

   atexit(&plugin_unload_all);

}


/*
 * unload all the plugin
 */

void plugin_unload_all(void)
{
   struct plugin_entry *p;
   
   DEBUG_MSG("ATEXIT: plugin_unload_all");   
   
   while (SLIST_FIRST(&plugin_head) != NULL) {
      p = SLIST_FIRST(&plugin_head);
      dlclose(p->handle);
      SLIST_REMOVE_HEAD(&plugin_head, next);
   }
   
//   if (lt_dlexit() != 0)
//      ERROR_MSG("lt_dlexit()");
}


/*
 * function used by plugins to register themself
 */
int plugin_register(void *handle, struct plugin_ops *ops)
{
   struct plugin_entry *p;

   if (strcmp(ops->ettercap_version, EC_VERSION)) {
      dlclose(handle);
      return -EVERSION;
   }

   p = calloc(1, sizeof(struct plugin_entry));
   ON_ERROR(p, NULL, "can't allocate memory");
   
   p->handle = handle;
   p->ops = ops;

   SLIST_INSERT_HEAD(&plugin_head, p, next);

   return ESUCCESS;
}

/* 
 * activate a plugin.
 * it launch the plugin init function 
 */

int plugin_init(char *name)
{
   struct plugin_entry *p;

   SLIST_FOREACH(p, &plugin_head, next) {
      if (!strcmp(p->ops->name, name)) {
         p->activated = 1;
         return p->ops->init(NULL);
      }
   }
   
   return -ENOTFOUND;
}

/* 
 * deactivate a plugin.
 * it launch the plugin fini function 
 */

int plugin_fini(char *name)
{
   struct plugin_entry *p;

   SLIST_FOREACH(p, &plugin_head, next) {
      if (p->activated == 1 && !strcmp(p->ops->name, name)) {
         p->activated = 0;
         return p->ops->fini(NULL);
      }
   }
   
   return -ENOTFOUND;
}

/*
 * it print the list of the plugins.
 *
 * func is the callback function to which are passed
 *    - the plugin name
 *    - the plugin version
 *    - the plugin description
 *
 * min is the n-th plugin to start to print
 * max it the n-th plugin to stop to print
 */

int plugin_list_print(int min, int max, void (*func)(char, struct plugin_ops *))
{
   struct plugin_entry *p;
   int i = min;

   SLIST_FOREACH(p, &plugin_head, next) {
      if (i > max)
         return (i-1);
      func(p->activated, p->ops);
      i++;
   }
   
   return (i == min) ? -ENOTFOUND : (i-1);
}

/* 
 * returns the type of the plugin 
 */

int plugin_get_type(char *name)
{
   struct plugin_entry *p;

   SLIST_FOREACH(p, &plugin_head, next) {
      if (!strcmp(p->ops->name, name)) {
         return p->ops->type;
      }
   }
   
   return -ENOTFOUND;
}

/*
 * returns the activation flag
 */

int plugin_is_activated(char *name)
{
   struct plugin_entry *p;

   SLIST_FOREACH(p, &plugin_head, next) {
      if (!strcmp(p->ops->name, name)) {
         return p->activated;
      }
   }
   
   return 0;
}

/* EOF */

// vim:ts=3:expandtab

