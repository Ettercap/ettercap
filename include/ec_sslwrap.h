
/* $Id: ec_sslwrap.h,v 1.1 2004/03/08 12:12:49 lordnaga Exp $ */

#ifndef EC_SSLWRAP_H
#define EC_SSLWRAP_H

#include <ec_decode.h>

extern void sslw_dissect_add(char *name, u_int32 port, FUNC_DECODER_PTR(decoder), u_char status);
extern void sslw_start(void);

#define SSL_ENABLED 1
#define SSL_DISABLED 0

#endif

/* EOF */

// vim:ts=3:expandtab

