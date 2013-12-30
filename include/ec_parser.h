#ifndef ETTERCAP_PARSER_H_DFCCFB7F7F4B41B5AFC9B69C17DC9903
#define ETTERCAP_PARSER_H_DFCCFB7F7F4B41B5AFC9B69C17DC9903

EC_API_EXTERN void parse_options(int argc, char **argv);

EC_API_EXTERN int expand_token(char *s, u_int max, void (*func)(void *t, u_int n), void *t );
EC_API_EXTERN int set_regex(char *regex);


#endif

/* EOF */

// vim:ts=3:expandtab

