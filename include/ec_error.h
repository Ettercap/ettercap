#ifndef ETTERCAP_ERROR_H
#define ETTERCAP_ERROR_H

#include <ec.h>
#include <errno.h>

enum {
   E_SUCCESS    = 0,
   E_NOTFOUND   = 1,
   E_NOMATCH    = 2,
   E_NOTHANDLED = 3,
   E_INVALID    = 4,
   E_NOADDRESS  = 5,
   E_DUPLICATE  = 6,
   E_TIMEOUT    = 7,
   E_INITFAIL   = 8,
   E_FOUND      = 128,
   E_BRIDGE     = 129,
   E_VERSION    = 254,
   E_FATAL      = 255,
};

EC_API_EXTERN void error_msg(char *file, const char *function, int line, char *message, ...);
EC_API_EXTERN void warn_msg(char *file, const char *function, int line, char *message, ...);
EC_API_EXTERN void fatal_error(char *message, ...);
EC_API_EXTERN void bug(char *file, const char *function, int line, char *message);


#define WARN_MSG(x, ...) warn_msg(__FILE__, __FUNCTION__, __LINE__, x, ## __VA_ARGS__ )
#define ERROR_MSG(x, ...) error_msg(__FILE__, __FUNCTION__, __LINE__, x, ## __VA_ARGS__ )

#define FATAL_ERROR(x, ...) do { fatal_error(x, ## __VA_ARGS__ ); } while(0)

#define ON_ERROR(x, y, fmt, ...) do { if (x == y) ERROR_MSG(fmt, ## __VA_ARGS__ ); } while(0)

#define BUG_IF(x) do { if (x) bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)

#define BUG(x) do { bug(__FILE__, __FUNCTION__, __LINE__, #x); }while(0)

#define NOT_IMPLEMENTED() do { BUG("Not yet implemented, please contact the authors"); } while(0)


#endif

/* EOF */

// vim:ts=3:expandtab

