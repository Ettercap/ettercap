
#ifndef EC_SESSION_H
#define EC_SESSION_H


struct session {
   void *ident;
   void *data;
   size_t data_len;
   int (*match)(void *id_sess, void *id);
};

extern void session_put(struct session *s);
extern int session_get(struct session **s, void *ident);
extern int session_del(void *ident);
extern int session_get_and_del(struct session **s, void *ident);
extern void session_free(struct session *s);
   

/* timeout in seconds */
#define SESSION_TIMEOUT 600


#endif

/* EOF */

// vim:ts=3:expandtab

