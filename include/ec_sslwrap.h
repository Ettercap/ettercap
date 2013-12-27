#ifndef ETTERCAP_SSLWRAP_H_D582AC4BFB5D4DE0B32C1132A9B46882
#define ETTERCAP_SSLWRAP_H_D582AC4BFB5D4DE0B32C1132A9B46882

#include <ec_decode.h>
#include <ec_threads.h>

EC_API_EXTERN void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status);
EC_API_EXTERN void sslw_dissect_move(char *name, u_int16 port);
EC_API_EXTERN EC_THREAD_FUNC(sslw_start);
EC_API_EXTERN void ssl_wrap_init(void);

#define SSL_DISABLED	0
#define SSL_ENABLED	1 

#endif

/* EOF */

// vim:ts=3:expandtab

