
#ifndef EC_ERROR_H
#define EC_ERROR_H

#include <errno.h>

extern void error_msg(char *file, char *function, int line, char *message, ...);

#define ERROR_MSG(x, args...) error_msg(__FILE__, __FUNCTION__, __LINE__, x, ## args)

#define FATAL_MSG(x, args...) do { fprintf(stderr, "\n"x"\n\n", ## args); exit(-1); } while(0)

#define ON_ERROR(x, y, fmt, args...) do { if (x == y) ERROR_MSG(fmt, ## args); } while(0)

#define NOT_IMPLEMENTED() do { ERROR_MSG("Not yet implemented"); } while(0)

enum {
   ESUCCESS    = 0,
   ENOTFOUND   = 1,
   ENOTHANDLED = 2,
   EINVALID    = 3,
   ENOADDRESS  = 4,
   EVERSION    = 5,
};

#endif

/* EOF */

// vim:ts=3:expandtab

