/*
    ettercap -- plugin handling

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/src/ec_plugins.c,v 1.2 2003/03/20 21:13:31 alor Exp $
*/

#include <ec.h>
#include <ec_plugins.h>
#include <ec_parser.h>

#include <dirent.h>
#include <dlfcn.h>

#ifdef OS_OPENBSD
/* The below define is a lie since we are really doing RTLD_LAZY since the
 * system doesn't support RTLD_NOW.
 */
   #define RTLD_NOW DL_LAZY
#endif

/* symbol prefix for some OSes */
#if defined(OS_OPENBSD) || defined(OS_DARWIN)
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
int plugin_load_single(char *path, char *name);
int plugin_register(void *handle, struct plugin_ops *ops);

/*******************************************/

/* 
 * load a plugin given the full path
 */

int plugin_load_single(char *path, char *name)
{
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
   
   //exit(0);
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


/* EOF */

// vim:ts=3:expandtab

