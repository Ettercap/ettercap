#ifndef ETTERCAP_PLUGINS_H
#define ETTERCAP_PLUGINS_H

#include <ec_stdint.h>
#include <ec_version.h>
#include <ec_ui.h>
#include <ec_threads.h>

struct plugin_ops
{
   char *ettercap_version;          /* ettercap version MUST be the global EC_VERSION */
   char *name;                      /* the name of the plugin */
   char *info;                      /* a short description of the plugin */
   char *version;                   /* the plugin version. note: 15 will be displayed as 1.5 */
   int (*init)(void *);          /* activation function */
   int (*fini)(void *);          /* deactivation function */
   int (*unload)(void *);          /* clean-up function */
};

struct plugin_list
{
   char *name;
   bool exists;
   LIST_ENTRY(plugin_list) next;
};

#ifdef OS_WINDOWS
  #define PLUGIN_PATTERN  "ec_*.dll"
#else
  #define PLUGIN_PATTERN  "ec_*.so"
#endif

EC_API_EXTERN void plugin_load_all(void);
EC_API_EXTERN int plugin_load_single(const char *path, char *name);
EC_API_EXTERN int plugin_register(void *handle, struct plugin_ops *ops);
EC_API_EXTERN int plugin_list_walk(int min, int max, void (*func)(char, struct plugin_ops *));
#define PLP_MIN   1
#define PLP_MAX   INT_MAX

EC_API_EXTERN int plugin_is_activated(char *name);
EC_API_EXTERN int search_plugin(char *name);

/* use these to activate and deactivate a plugin; these are *imported* from plugins */
EC_API_EXTERN int plugin_init(char *name);
EC_API_EXTERN int plugin_fini(char *name);
EC_API_EXTERN int plugin_kill_thread(char *name, char *thread);

#define PLUGIN_UNLOADED -1
#define PLUGIN_FINISHED 0
#define PLUGIN_RUNNING  1

EC_API_EXTERN void plugin_list(void);
EC_API_EXTERN void free_plugin_list(struct plugin_list_t plugins);

#define PLUGIN_LOCK(x)                                \
   do{                                                \
       if (pthread_mutex_trylock(&x)) {               \
          ec_thread_exit();                           \
          return NULL;                                \
       }                                              \
   } while(0)

#define PLUGIN_UNLOCK(x)                              \
   do{                                                \
       pthread_mutex_unlock(&x);                      \
   } while(0)

#endif 

/* EOF */

// vim:ts=3:expandtab

