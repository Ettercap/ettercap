
/* $Id: ec_ui.h,v 1.15 2004/05/07 09:54:37 alor Exp $ */

#ifndef EC_UI_H
#define EC_UI_H

#include <stdarg.h>

struct ui_ops {
   void (*init)(void);
   void (*start)(void);
   void (*cleanup)(void);
   void (*msg)(const char *msg);
   void (*error)(const char *msg);
   void (*fatal_error)(const char *msg);
   void (*input)(const char *title, char *input, size_t n, void (*callback)(void));
   void (*progress)(char *title, int value, int max);
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
extern void ui_fatal_error(const char *msg);
extern void ui_input(const char *title, char *input, size_t n, void (*callback)(void));
extern void ui_progress(char *title, int value, int max);
extern int ui_msg_flush(int max);
#define MSG_ALL   INT_MAX

extern int ui_msg_purge_all(void);
extern void ui_register(struct ui_ops *ops);

#define USER_MSG(x, ...) ui_msg(x, ## __VA_ARGS__ )

#define INSTANT_USER_MSG(x, ...) do { ui_msg(x, ## __VA_ARGS__ ); ui_msg_flush(MSG_ALL); } while(0)

#define FATAL_MSG(x, ...) do { ui_error(x, ## __VA_ARGS__ ); return (-EFATAL); } while(0)

/* 
 * if we are using the text interface, exit with a fatal error,
 * else display a message and continue with the current GUI (curses or gtk)
 */
#define SEMIFATAL_ERROR(x, ...) do {                              \
   if (!GBL_UI->initialized || GBL_UI->type == UI_TEXT || GBL_UI->type == UI_DAEMONIZE)   \
      FATAL_ERROR(x, ## __VA_ARGS__);                             \
   else                                                           \
      FATAL_MSG(x, ## __VA_ARGS__);                               \
} while(0)

#endif

/* EOF */

// vim:ts=3:expandtab

