
/* $Id: ec_error.h,v 1.11 2003/09/18 22:15:01 alor Exp $ */

#ifndef EC_ERROR_H
#define EC_ERROR_H

#include <errno.h>

enum {
   ESUCCESS    = 0,
   ENOTFOUND   = 1,
   ENOMATCH    = 2,
   ENOTHANDLED = 3,
   EINVALID    = 4,
   ENOADDRESS  = 5,
   EVERSION    = 254,
   EFATAL      = 255,
};

extern void error_msg(char *file, char *function, int line, char *message, ...);
extern void bug(char *file, char *function, int line, char *message);

#define ERROR_MSG(x, ...) error_msg(__FILE__, __FUNCTION__, __LINE__, x, ## __VA_ARGS__ )

#define FATAL_ERROR(x, ...) do { fprintf(stderr, "\n"x"\n\n", ## __VA_ARGS__ ); _exit(-1); } while(0)

#define ON_ERROR(x, y, fmt, ...) do { if (x == y) ERROR_MSG(fmt, ## __VA_ARGS__ ); } while(0)

#define BUG_IF(x) do { if (x) bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)

#define BUG(x) do { bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)

#define NOT_IMPLEMENTED() do { BUG("Not yet implemented"); } while(0)


#endif

/* EOF */

// vim:ts=3:expandtab

