
/* $Id: ec_sslwrap.h,v 1.3 2004/03/09 22:25:31 lordnaga Exp $ */

#ifndef EC_SSLWRAP_H
#define EC_SSLWRAP_H

#include <ec_decode.h>
#include <ec_threads.h>

extern void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status);
extern EC_THREAD_FUNC(sslw_start);

#define SSL_DISABLED	0
#define SSL_ENABLED	((u_int16)(1)) 
#define SSL_PEER_DONE	((u_int16)(1<<1))
#define SSL_CONN_DONE	((u_int16)(1<<2))
#define SSL_CTX_DONE	((u_int16)(1<<3))
#define SSL_SERV_DONE	((u_int16)(1<<4))
#define SSL_CLNT_DONE	((u_int16)(1<<5))

#endif

/* EOF */

// vim:ts=3:expandtab

