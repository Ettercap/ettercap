
#ifndef EL_FUNCTIONS_H
#define EL_FUNCTIONS_H

#include <ec_log.h>
#include <ec_profiles.h>

/* el_parser */
extern void parse_options(int argc, char **argv);
extern void expand_token(char *s, u_int max, void (*func)(void *t, int n), void *t );
extern int match_pattern(const char *s, const char *pattern);

/* el_analyze */
extern void analyze(void);
extern void create_hosts_list(void);

/* el_main */
extern void progress(int value, int max);

/* el_log */
extern void open_log(char *file);
extern int get_header(struct log_global_header *hdr);
extern int get_packet(struct log_header_packet *pck, u_char **buf);
extern int get_info(struct log_header_info *inf, struct dissector_info *buf);

/* el_display */
extern void display(void);
extern void set_display_regex(char *regex);

/* el_conn */
extern void conn_table(void);
extern void filcon_compile(char *conn);
extern int is_conn(struct log_header_packet *pck, int *versus);
#define VERSUS_SOURCE   0
#define VERSUS_DEST     1 

/* el_target */
extern void target_compile(char *target);
extern int is_target_pck(struct log_header_packet *pck);
extern int is_target_info(struct log_header_info *inf);

/* el_profiles */
extern int profile_add_info(struct log_header_info *inf);

#endif

/* EOF */

// vim:ts=3:expandtab

