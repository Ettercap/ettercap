
/* $Id: wdg.h,v 1.11 2003/11/02 20:36:44 alor Exp $ */

#ifndef WDG_H
#define WDG_H

#ifdef HAVE_CONFIG_H
   #include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <missing/queue.h>

/********************************************/

enum {
   WDG_ESUCCESS    = 0,
   WDG_ENOTHANDLED = 1,
   WDG_EFATAL      = 255,
};

extern void wdg_error_msg(char *file, char *function, int line, char *message, ...);
#define WDG_ON_ERROR(x, y, fmt, ...) do { if (x == y) wdg_error_msg(__FILE__, __FUNCTION__, __LINE__, fmt, ## __VA_ARGS__ ); } while(0)

extern void wdg_bug(char *file, char *function, int line, char *message);
#define WDG_BUG_IF(x) do { if (x) wdg_bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)
#define WDG_NOT_IMPLEMENTED() do { wdg_bug(__FILE__, __FUNCTION__, __LINE__, "Not yet implemented"); } while(0)

#define WDG_SAFE_CALLOC(x, n, s) do { \
   x = calloc(n, s); \
   WDG_ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define WDG_SAFE_REALLOC(x, s) do { \
   x = realloc(x, s); \
   WDG_ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define WDG_SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define WDG_EXECUTE(x, ...) do{ if(x != NULL) x( __VA_ARGS__ ); }while(0)

#define WDG_LOOP for(;;)

/* used by halfdelay */
#define WDG_INPUT_TIMEOUT  1

/* not defined in curses.h */
#define KEY_RETURN   '\r'
#define KEY_TAB      '\t'
#define KEY_CTRL_L   12

/* informations about the current screen */
struct wdg_scr {
   size_t lines;
   size_t cols;
   size_t flags;
      #define WDG_SCR_HAS_COLORS    1
      #define WDG_SCR_INITIALIZED   (1<<1)
};

/* global scruct for current screen */
extern struct wdg_scr current_screen;

/* struct for mouse events */
struct wdg_mouse_event {
   size_t x;
   size_t y;
   size_t event;
};

#define WDG_MOUSE_ENCLOSE(win, key, mouse) (key == KEY_MOUSE && wenclose(win, mouse->y, mouse->x))

/* struct for all wdg objects */
struct wdg_object {
   /* object flags */
   size_t flags;
      #define WDG_OBJ_WANT_FOCUS     1
      #define WDG_OBJ_FOCUS_MODAL    (1<<1)
      #define WDG_OBJ_FOCUSED        (1<<2)
      #define WDG_OBJ_VISIBLE        (1<<3)
      #define WDG_OBJ_ROOT_OBJECT    (1<<7)
   /* object type */
   size_t type;
      #define WDG_WINDOW      1
      #define WDG_PANEL       2
      #define WDG_SCROLL      3
      #define WDG_MENU        4
   
   /* destructor function */
   int (*destroy)(struct wdg_object *wo);
   /* called to set / reset the size */
   int (*resize)(struct wdg_object *wo);
   /* called upon redrawing of the object */
   int (*redraw)(struct wdg_object *wo);
   /* get / lost focus redrawing functions */
   int (*get_focus)(struct wdg_object *wo);
   int (*lost_focus)(struct wdg_object *wo);
   /* called to process an input from the user */
   int (*get_msg)(struct wdg_object *wo, int key, struct wdg_mouse_event *mouse);

   /* object cohordinates */
   int x1, y1, x2, y2;

   /* object colors */
   u_char screen_color;
   u_char border_color;
   u_char focus_color;
   u_char title_color;
   u_char window_color;
   u_char select_color;

   /* title */
   char *title;
   char align;

   /* here is the pointer to extend a wdg object
    * it is a sort of inheritance...
    */
   void *extend;
};

typedef struct wdg_object wdg_t;

/* WIDGETS */

#define WDG_MOVE_PANEL(pan, y, x)   do{ WDG_ON_ERROR(move_panel(pan, y, x), ERR, "Resized too much... (%d,%d)", x, y); }while(0)
#define WDG_WRESIZE(win, l, c)   do{ WDG_ON_ERROR(wresize(win, l, c), ERR, "Resized too much...(%dx%d)", c, l); }while(0)

#define WDG_WO_EXT(type, var) type *var = (type *)(wo->extend);

/* alignment */
#define WDG_ALIGN_LEFT     0
#define WDG_ALIGN_CENTER   1
#define WDG_ALIGN_RIGHT    2

/* window ojbects */
extern void wdg_window_print(wdg_t *wo, size_t x, size_t y, char *fmt, ...);
/* panel ojbects */
extern void wdg_panel_print(wdg_t *wo, size_t x, size_t y, char *fmt, ...);
/* scroll ojbects */
extern void wdg_scroll_print(wdg_t *wo, char *fmt, ...);
extern void wdg_scroll_set_lines(wdg_t *wo, size_t lines);
/* menu objects */
struct wdg_menu {
   char *name;
   char *shortcut;
   void (*callback)(void);
};
extern void wdg_menu_add(wdg_t *wo, struct wdg_menu *menu);


/* EXPORTED FUNCTIONS */

extern void wdg_init(void);
extern void wdg_cleanup(void);
extern void wdg_redraw_all(void);

/* the main dispatching loop */
extern int wdg_events_handler(int exit_key);
/* add/delete functions to be called when idle */
extern void wdg_add_idle_callback(void (*callback)(void));
extern void wdg_del_idle_callback(void (*callback)(void));

/* object creation */
extern int wdg_create_object(wdg_t **wo, size_t type, size_t flags);
extern int wdg_destroy_object(wdg_t **wo);

/* object modifications */
extern void wdg_set_size(wdg_t *wo, int x1, int y1, int x2, int y2);
extern void wdg_set_colors(wdg_t *wo, int color, size_t type); 
extern void wdg_draw_object(wdg_t *wo);
extern size_t wdg_get_type(wdg_t *wo);
extern void wdg_set_focus(wdg_t *wo);
extern void wdg_set_title(wdg_t *wo, char *title, size_t align);
extern void wdg_init_color(u_char pair, u_char fg, u_char bg);
extern void wdg_set_color(wdg_t *wo, size_t part, u_char pair);
   #define WDG_COLOR_SCREEN   0
   #define WDG_COLOR_TITLE    1
   #define WDG_COLOR_BORDER   2
   #define WDG_COLOR_FOCUS    3
   #define WDG_COLOR_WINDOW   4
   #define WDG_COLOR_SELECT   5

/* object size */
extern size_t wdg_get_nlines(wdg_t *wo);
extern size_t wdg_get_ncols(wdg_t *wo);
extern size_t wdg_get_begin_x(wdg_t *wo);
extern size_t wdg_get_begin_y(wdg_t *wo);

#endif 

/* EOF */

// vim:ts=3:expandtab

