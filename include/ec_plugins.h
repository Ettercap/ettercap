
#ifndef EC_PLUGINS_H
#define EC_PLUGINS_H

#include <ec_stdint.h>
#include <ec_version.h>
#include <ec_ui.h>

struct plugin_ops
{
   char *ettercap_version;          /* ettercap version MUST be the global EC_VERSION */
   char *name;                      /* the name of the plugin */
   char *info;                      /* a short description of the plugin */
   char *version;                   /* the plugin version. note: 15 will be displayed as 1.5 */
   int type;                        /* the pluging type: standalone (executed as a thread)
                                     *                   hook (uses hook points)
                                     */
#define PL_STANDALONE   0
#define PL_HOOK         1
   int (*init)(void *);          /* activation function */
   int (*fini)(void *);          /* deactivation function */
};

#define PLUGIN_PATTERN   "ec_*.so"

extern void plugin_load_all(void);
extern int plugin_register(void *handle, struct plugin_ops *ops);
extern int plugin_list_print(int min, int max, void (*func)(char, struct plugin_ops *));
#define PLP_MIN   1
#define PLP_MAX   INT32_MAX

extern int plugin_get_type(char *name);

/* use these to activate and deactivate a plugin */
extern int plugin_init(char *name);
extern int plugin_fini(char *name);

#endif 

/* EOF */

// vim:ts=3:expandtab

