
/* $Id: ec_socket.h,v 1.3 2003/10/14 16:54:00 alor Exp $ */

#ifndef EC_SOCKET_H
#define EC_SOCKET_H

extern int open_socket(char *host, u_int16 port);
extern int close_socket(int s);
extern void set_blocking(int s, int set);
extern int socket_send(int s, u_char *payload, size_t size);
extern int socket_recv(int s, u_char *payload, size_t size);

#endif

/* EOF */

// vim:ts=3:expandtab

