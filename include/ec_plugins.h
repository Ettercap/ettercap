
#if !defined(EC_PLUGINS_H)
#define EC_PLUGINS_H

struct plugin_ops
{
   char *ettercap_version;          /* ettercap version MUST be the global VERSION */
   char *plug_info;                 /* a short description of the plugin */
   char plug_version;               /* the plugin version. note: 15 will be displayed as 1.5 */
   char plug_type;                  /* the pluging type: external (old style) or hooking (new style) */
#define PT_EXT  0
#define PT_HOOK 1
   char hook_point;                 /* the hook point */
#define HOOK_NONE                   0
#define PCK_RECEIVED_RAW            1
#define PCK_RECEIVED_STRUCT_FILLED  2
#define PCK_PRE_FORWARD             3
#define PCK_DISSECTOR               4
#define PCK_DECODED                 5
   int (*hook_function)(void *);    /* the function to be executed at the hook point */
};


struct plugin_attr
{
   void *handle;
   char *name;
   char *path;
   char enabled;
   int (*init_function)(void *);
   int (*fini_function)(void *);
   struct plugin_ops ops;
};


struct plug_array
{
   char *name;
   float version;
   char *description;
   char status;
};

extern int Plugin_Register(void *, struct plugin_ops *);
extern void Plugin_LoadAll(void);
extern int Plugin_Load(char *name, char *path);
extern int Plugin_UnLoad(char *name);
extern void Plugin_HookPoint(char hook_point, void *args);
extern int Plugin_RunExt(char *name);
extern char * Plugin_Getname(char *file);
extern char * Plugin_Getfile(char *name, char *path);
extern char ** Plugin_ExtList(void);
extern int Plugin_ExtArray(void);
extern void Plugin_SetActivation(char *name, char status);

extern int Plugin_Input(char *string, size_t size, short mode);
extern void Plugin_Output(char *message, ...);
extern void Plugin_Hook_Output(char *message, ...);

#define P_BLOCK      1
#define P_NONBLOCK   0

#include <string.h>

#endif // EC_PLUGINS_H

/* EOF */

// vim:ts=3:expandtab

