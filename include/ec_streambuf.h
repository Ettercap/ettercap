
/* $Id: ec_streambuf.h,v 1.4 2003/10/19 16:46:16 lordnaga Exp $ */

#ifndef EC_STREAMBUF_H
#define EC_STREAMBUF_H

#include <ec_threads.h>

struct stream_buf {
   /* the lock */
   pthread_mutex_t streambuf_mutex;
   /* Last TCP Sequence Number if we are using it for TCP streaming */
   u_int32 tcp_seq;
   /* total size */
   size_t size;
   /* the real buffer made up of a tail of packets */
   TAILQ_HEAD(streambuf_head, stream_pck_list) streambuf_tail;
};

/* an entry in the tail */
struct stream_pck_list {
   /* size of the element */
   size_t size;
   /* pointer to the last read byte */
   size_t ptr;
   /* the data */
   u_char *buf;
   /* the link to the next element */
   TAILQ_ENTRY(stream_pck_list) next;
};

/* functions */
extern void streambuf_init(struct stream_buf *sb);
extern int streambuf_add(struct stream_buf *sb, struct packet_object *po);
extern int streambuf_seq_add(struct stream_buf *sb, struct packet_object *po);
extern int streambuf_get(struct stream_buf *sb, u_char *buf, size_t len, int mode);
extern void streambuf_wipe(struct stream_buf *sb);
extern int streambuf_read(struct stream_buf *sb, u_char *buf, size_t len, int mode);

#define STREAM_ATOMIC   0
#define STREAM_PARTIAL  1

#endif

/* EOF */

// vim:ts=3:expandtab

