
#ifndef EF_FUNCTIONS_H
#define EF_FUNCTIONS_H

/* ef_parser */
extern void parse_options(int argc, char **argv);

/* ef_test */
extern void test_filter(void);

/* ef_syntax && ef_grammar */
extern int yyerror(char *);                                                                         
extern int yylex(void);

/* ef_tables */
extern void load_tables(void);
extern int get_virtualpointer(char *name, char *offname, u_int8 *level, u_int16 *offset, u_int8 *size);

#endif

/* EOF */

// vim:ts=3:expandtab

