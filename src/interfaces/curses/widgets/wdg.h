
/* $Id: wdg.h,v 1.6 2003/10/23 19:50:58 uid42100 Exp $ */

#ifndef WDG_H
#define WDG_H

#ifdef HAVE_CONFIG_H
   #include <config.h>
#endif

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

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

#define WDG_SAFE_FREE(x) do{ if(x) { free(x); x = NULL; } }while(0)

#define WDG_EXECUTE(x, ...) do{ if(x != NULL) x( __VA_ARGS__ ); }while(0)

#define WDG_LOOP for(;;)

/* used by halfdelay */
#define WDG_INPUT_TIMEOUT  1


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

/* struct for all wdg objects */
struct wdg_object {
   /* object flags */
   size_t flags;
      #define WDG_OBJ_WANT_FOCUS     1
      #define WDG_OBJ_FOCUS_MODAL    (1<<1)
      #define WDG_OBJ_VISIBLE        (1<<2)
      #define WDG_OBJ_ROOT_OBJECT    (1<<7)
   /* object type */
   size_t type;
      #define WDG_WINDOW      1
   
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
   int (*get_msg)(struct wdg_object *wo, int key);

   /* object size */
   int x1, y1, x2, y2;

   /* here is the pointer to extend a wdg object
    * it is a sort of inheritance...
    */
   void *extend;
};

typedef struct wdg_object wdg_t;

/* WIDGETS */


/* EXPORTED FUNCTIONS */

extern void wdg_init(void);
extern void wdg_cleanup(void);

/* the main dispatching loop */
extern int wdg_events_handler(int exit_key);
/* add/delete functions to be called when idle */
extern void wdg_add_idle_callback(void (*callback)(void));
extern void wdg_del_idle_callback(void (*callback)(void));

/* object creation */
extern int wdg_create_object(struct wdg_object **wo, size_t type, size_t flags);
extern int wdg_destroy_object(struct wdg_object **wo);

/* object modifications */
extern void wdg_resize_object(struct wdg_object *wo, int x1, int y1, int x2, int y2);
extern void wdg_set_colors(struct wdg_object *wo, int color, size_t type); 
extern void wdg_draw_object(struct wdg_object *wo);
extern size_t wdg_get_type(struct wdg_object *wo);
extern void wdg_set_focus(struct wdg_object *wo);

#endif 

/* EOF */

// vim:ts=3:expandtab

