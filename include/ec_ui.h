
/* $Id: ec_ui.h,v 1.10 2003/10/11 19:43:42 alor Exp $ */

#ifndef EC_UI_H
#define EC_UI_H

#include <stdarg.h>

struct ui_ops {
   void (*init)(void);
   void (*start)(void);
   void (*cleanup)(void);
   void (*msg)(const char *msg);
   void (*error)(const char *msg);
   void (*progress)(int value, int max);
   char initialized;
   char type;
      #define UI_TEXT      0
      #define UI_DAEMONIZE 1
      #define UI_CURSES    2
      #define UI_GTK       3
};

extern void ui_init(void);
extern void ui_start(void);
extern void ui_cleanup(void);
extern void ui_msg(const char *fmt, ...);
extern void ui_error(const char *fmt, ...);
extern void ui_progress(int value, int max);
extern int ui_msg_flush(int max);
#define MSG_ALL   INT_MAX

extern int ui_msg_purge_all(void);
extern void ui_register(struct ui_ops *ops);

#define USER_MSG(x, ...) ui_msg(x, ## __VA_ARGS__ )

#define FATAL_MSG(x, ...) do { ui_error(x, ## __VA_ARGS__ ); return (-EFATAL); } while(0)

#endif

/* EOF */

// vim:ts=3:expandtab

