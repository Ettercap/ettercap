
#if defined (DEBUG) && !defined(EC_DEBUG_H)
#define EC_DEBUG_H

extern void debug_init(void);
extern void debug_msg(const char *message, ...);

extern FILE *debug_file;

#define DEBUG_INIT() debug_init()
#define DEBUG_MSG(x, ...) do {                                 \
   if (debug_file == NULL) {                                   \
      FATAL_ERROR("[%s::%s] DEBUG_MSG called before initialization !!", __FILE__, __FUNCTION__); \
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

