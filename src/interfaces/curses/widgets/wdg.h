
/* $Id: wdg.h,v 1.4 2003/10/22 08:05:44 alor Exp $ */

#ifndef WDG_H
#define WDG_H

#ifdef HAVE_CONFIG_H
   #include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#ifdef HAVE_SYS_QUEUE
   #include <sys/queue.h>
#else
   #include <missing/queue.h>
#endif

extern void error_msg(char *file, char *function, int line, char *message, ...);
#define WDG_ON_ERROR(x, y, fmt, ...) do { if (x == y) error_msg(fmt, ## __VA_ARGS__ ); } while(0)

extern void bug(char *file, char *function, int line, char *message);
#define WDG_BUG_IF(x) do { if (x) bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)
#define WDG_NOT_IMPLEMENTED() do { bug(__FILE__, __FUNCTION__, __LINE__, "Not yet implemented"); } while(0)

#define WDG_SAFE_CALLOC(x, n, s) do { \
   x = calloc(n, s); \
   WDG_ON_ERROR(x, NULL, "virtual memory exhausted"); \
} while(0)

#define WDG_SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define WDG_EXECUTE(x, ...) do{ if(x != NULL) x( __VA_ARGS__ ); }while(0)

#define WDG_LOOP for(;;)

/* used by halfdelay */
#define WDG_INPUT_TIMEOUT  1

enum {
   WDG_ESUCCESS    = 0,
   WDG_ENOTHANDLED = 1,
   WDG_EFATAL      = 255,
};

/* informations about the current screen */
struct wdg_scr {
   size_t lines;
   size_t cols;
   char colors;
   char initialized;
};

/* global scruct for current screen */
extern struct wdg_scr current_screen;

/* struct for all wdg objects */
struct wdg_object {
   /* object flags */
   size_t flags;
      #define WDG_WANT_FOCUS     1
      #define WDG_VISIBLE        (1<<1)
      #define WDG_ROOT_OBJECT    (1<<7)

   /* destructor function */
   int (*destroy)(void);
   /* called to set / reset the size */
   int (*resize)(size_t x1, size_t y1, size_t x2, size_t y2);
   /* called upon redrawing of the object */
   int (*redraw)(void);
   /* get / lost focus redrawing functions */
   int (*get_focus)(void);
   int (*lost_focus)(void);
   /* called to process an input from the user */
   int (*get_msg)(int key);

   /* here is the pointer to extend a wdg object
    * it is a sort of inheritance...
    */
   void *extend;
};

/* WIDGETS */

/* EXPORTED FUNCTIONS */

extern void wdg_init(void);
extern void wdg_cleanup(void);

/* the main dispatching loop */
extern int wdg_events_handler(int exit_key);
/* se the function to be called when idle */
extern void wdg_set_idle_callback(void (*callback)(void));

/* object creation */
extern int wdg_create_object(struct wdg_object **wo, size_t type, size_t flags);
extern int wdg_destroy_object(struct wdg_object **wo);

/* object modifications */
extern int wdg_resize_object(struct wdg_object *wo, size_t x1, size_t y1, size_t x2, size_t y2);
extern int wdg_set_colors(struct wdg_object *wo, size_t gb, size_t fg, size_t border, size_t focus, size_t title);

#endif 

/* EOF */

// vim:ts=3:expandtab

