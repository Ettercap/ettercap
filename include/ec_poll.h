
/* $Id: ec_poll.h,v 1.4 2004/07/20 09:53:52 alor Exp $ */

#ifndef EC_POLL_H
#define EC_POLL_H


extern int ec_poll_in(int fd, u_int msec);
extern int ec_poll_out(int fd, u_int msec);
extern int ec_poll_buffer(char *buf);

#endif

/* EOF */

// vim:ts=3:expandtab

