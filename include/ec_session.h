
/* $Id: ec_session.h,v 1.4 2003/09/18 22:15:02 alor Exp $ */

#ifndef EC_SESSION_H
#define EC_SESSION_H


struct session {
   void *ident;
   size_t ident_len;
   void *data;
   size_t data_len;
   int (*match)(void *id_sess, void *id);
};

extern void session_put(struct session *s);
extern int session_get(struct session **s, void *ident, size_t ident_len);
extern int session_del(void *ident, size_t ident_len);
extern int session_get_and_del(struct session **s, void *ident, size_t ident_len);
extern void session_free(struct session *s);
   

#endif

/* EOF */

// vim:ts=3:expandtab

