
/* $Id: ec_socket.h,v 1.4 2004/07/12 19:57:26 alor Exp $ */

#ifndef EC_SOCKET_H
#define EC_SOCKET_H

/* The never ending errno problems... */
#if defined(OS_WINDOWS) && !defined(OS_CYGWIN)
    #define GET_SOCK_ERRNO()  WSAGetLastError()
#else
    #define GET_SOCK_ERRNO()  errno
#endif

extern int open_socket(char *host, u_int16 port);
extern int close_socket(int s);
extern void set_blocking(int s, int set);
extern int socket_send(int s, u_char *payload, size_t size);
extern int socket_recv(int s, u_char *payload, size_t size);

#endif

/* EOF */

// vim:ts=3:expandtab

