
#ifndef EC_CONNBUF_H
#define EC_CONNBUF_H

#include <ec_inet.h>

struct conn_buf {
   /* max buffer size */
   size_t max_size;
   /* actual buffer size */
   size_t size;
   /* the real buffer made up of a tail of packets */
   TAILQ_HEAD(first, pck_list) buf_tail;
};

/* an entry in the tail */
struct pck_list {
   /* size of the element (including the struct size) */
   size_t size;
   /* the source of the packet */
   struct ip_addr L3_src;
   /* the data */
   u_char *buf;
   /* the link to the next element */
   TAILQ_ENTRY(pck_list) next;
};

/* functions */
extern void connbuf_init(struct conn_buf *cb, size_t size);
extern int connbuf_add(struct conn_buf *cb, struct packet_object *po);
extern void connbuf_wipe(struct conn_buf *cb);
extern int connbuf_print(struct conn_buf *cb, struct ip_addr *L3_src, void (*)(u_char *, size_t));


#endif

/* EOF */

// vim:ts=3:expandtab

