
/* $Id: ec_debug.h,v 1.8 2003/10/29 22:38:19 alor Exp $ */

#if defined (DEBUG) && !defined(EC_DEBUG_H)
#define EC_DEBUG_H

extern void debug_init(void);
extern void debug_msg(const char *message, ...);

extern FILE *debug_file;

#define DEBUG_INIT() debug_init()
#define DEBUG_MSG(x, ...) do {                                 \
   if (debug_file == NULL) {                                   \
      fprintf(stderr, "DEBUG: "x"\n", ## __VA_ARGS__ );            \
   } else                                                      \
      debug_msg(x, ## __VA_ARGS__ );                           \
} while(0)

#endif /* EC_DEBUG_H */

/* 
 * if DEBUG is not defined we expand the macros to null instructions...
 */

#ifndef DEBUG
   #define DEBUG_INIT()
   #define DEBUG_MSG(x, ...)
#endif

/* EOF */

// vim:ts=3:expandtab

