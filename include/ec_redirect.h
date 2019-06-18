#ifndef ETTERCAP_REDIRECT_H
#define ETTERCAP_REDIRECT_H

typedef enum {
   EC_REDIR_ACTION_INSERT,
   EC_REDIR_ACTION_REMOVE
} ec_redir_act_t;

typedef enum {
   EC_REDIR_PROTO_IPV4,
   EC_REDIR_PROTO_IPV6
} ec_redir_proto_t;

struct redir_entry {
   char                   *name;
   ec_redir_proto_t        proto;
   char                   *source;
   char                   *destination;
   u_int16                 from_port;
   u_int16                 to_port;
   LIST_ENTRY(redir_entry) next;
};

struct serv_entry {
   char  *name;
   u_int16  from_port;
   u_int16  to_port;
   SLIST_ENTRY(serv_entry) next;
};

/* proto */
EC_API_EXTERN int ec_redirect(ec_redir_act_t action, char *name,
      ec_redir_proto_t proto, const char *source, const char *destination,
      u_int16 sport, u_int16 dport);
EC_API_EXTERN int ec_walk_redirects(void (*func)(struct redir_entry*));
EC_API_EXTERN int ec_walk_redirect_services(void (*func)(struct serv_entry*));
EC_API_EXTERN void ec_redirect_cleanup(void);


#endif

/* EOF */

// vim:ts=3:expandtab

