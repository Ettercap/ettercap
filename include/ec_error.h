
#ifndef EC_ERROR_H
#define EC_ERROR_H

#include <errno.h>

enum {
   ESUCCESS    = 0,
   ENOTFOUND   = 1,
   ENOTHANDLED = 2,
   EINVALID    = 3,
   ENOADDRESS  = 4,
   EVERSION    = 5,
   EFATAL      = 255,
};

extern void error_msg(char *file, char *function, int line, char *message, ...);
extern void bug(char *file, char *function, int line, char *message);

#define ERROR_MSG(x, ...) error_msg(__FILE__, __FUNCTION__, __LINE__, x, ## __VA_ARGS__ )

#define FATAL_ERROR(x, ...) do { fprintf(stderr, "\n"x"\n\n", ## __VA_ARGS__ ); exit(-1); } while(0)

#define FATAL_MSG(x, ...) do { ui_error(x, ## __VA_ARGS__ ); return (-EFATAL); } while(0)

#define ON_ERROR(x, y, fmt, ...) do { if (x == y) ERROR_MSG(fmt, ## __VA_ARGS__ ); } while(0)

#define BUG_IF(x, y) do { if (x == y) bug(__FILE__, __FUNCTION__, __LINE__, #x" is equal to "#y); }while(0)

#define NOT_IMPLEMENTED() do { ERROR_MSG("Not yet implemented"); } while(0)


#endif

/* EOF */

// vim:ts=3:expandtab

