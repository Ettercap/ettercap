
#ifndef EC_UI_H
#define EC_UI_H

#include <stdarg.h>

struct ui_ops {
   void (*init)(void);
   void (*start)(void);
   void (*cleanup)(void);
   void (*msg)(const char *msg);
   char initialized;
};

extern void ui_init(void);
extern void ui_start(void);
extern void ui_cleanup(void);
extern void ui_msg(const char *fmt, ...);
extern int ui_msg_flush(int max);
extern void ui_register(struct ui_ops *ops);

#define USER_MSG(x, args...) ui_msg(x, ## args )


#endif

/* EOF */

// vim:ts=3:expandtab

