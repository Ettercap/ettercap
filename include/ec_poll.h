#ifndef ETTERCAP_POLL_H
#define ETTERCAP_POLL_H

EC_API_EXTERN int ec_poll_in(int fd, u_int msec);
EC_API_EXTERN int ec_poll_out(int fd, u_int msec);
EC_API_EXTERN int ec_poll_buffer(char *buf);

#endif

/* EOF */

// vim:ts=3:expandtab

