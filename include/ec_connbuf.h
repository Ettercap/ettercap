
/* $Id: ec_connbuf.h,v 1.4 2003/09/18 22:15:01 alor Exp $ */

#ifndef EC_CONNBUF_H
#define EC_CONNBUF_H

#include <ec_inet.h>
#include <ec_threads.h>

struct conn_buf {
   /* the lock */
   pthread_mutex_t connbuf_mutex;
   /* max buffer size */
   size_t max_size;
   /* actual buffer size */
   size_t size;
   /* the real buffer made up of a tail of packets */
   TAILQ_HEAD(connbuf_head, conn_pck_list) connbuf_tail;
};

/* an entry in the tail */
struct conn_pck_list {
   /* size of the element (including the struct size) */
   size_t size;
   /* the source of the packet */
   struct ip_addr L3_src;
   /* the data */
   u_char *buf;
   /* the link to the next element */
   TAILQ_ENTRY(conn_pck_list) next;
};

/* functions */
extern void connbuf_init(struct conn_buf *cb, size_t size);
extern int connbuf_add(struct conn_buf *cb, struct packet_object *po);
extern void connbuf_wipe(struct conn_buf *cb);
extern int connbuf_print(struct conn_buf *cb, struct ip_addr *L3_src, void (*)(u_char *, size_t));


#endif

/* EOF */

// vim:ts=3:expandtab

