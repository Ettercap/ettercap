#ifndef ETTERCAP_UTILS_H_2E32BC706F2B40A79C7061E755E4AC67
#define ETTERCAP_UTILS_H_2E32BC706F2B40A79C7061E755E4AC67

EC_API_EXTERN int expand_token(char *s, u_int max, void (*func)(void *t, u_int n), void *t );
EC_API_EXTERN int set_regex(char *regex);
EC_API_EXTERN char **parse_iflist(char *list);
EC_API_EXTERN void drop_privs(void);
EC_API_EXTERN void regain_privs(void);

#endif
