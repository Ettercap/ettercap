
/* $Id: ec_sslwrap.h,v 1.5 2004/03/25 21:25:27 lordnaga Exp $ */

#ifndef EC_SSLWRAP_H
#define EC_SSLWRAP_H

#include <ec_decode.h>
#include <ec_threads.h>

extern void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status);
extern void sslw_dissect_move(char *name, u_int16 port);
extern EC_THREAD_FUNC(sslw_start);
extern void ssl_wrap_init(void);

#define SSL_DISABLED	0
#define SSL_ENABLED	1 

#endif

/* EOF */

// vim:ts=3:expandtab

