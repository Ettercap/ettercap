
/* $Id: ec_sslwrap.h,v 1.4 2004/03/10 21:51:20 lordnaga Exp $ */

#ifndef EC_SSLWRAP_H
#define EC_SSLWRAP_H

#include <ec_decode.h>
#include <ec_threads.h>

extern void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status);
extern EC_THREAD_FUNC(sslw_start);

#define SSL_DISABLED	0
#define SSL_ENABLED	1 

#endif

/* EOF */

// vim:ts=3:expandtab

