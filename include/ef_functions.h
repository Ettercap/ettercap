
/* $Id: ef_functions.h,v 1.10 2003/09/27 17:22:02 alor Exp $ */

#ifndef EF_FUNCTIONS_H
#define EF_FUNCTIONS_H

#define SCRIPT_ERROR(x, ...) FATAL_ERROR("[%s:%d]: "x, GBL_OPTIONS.source_file, GBL.lineno, ## __VA_ARGS__ );

/* ef_parser */
extern void parse_options(int argc, char **argv);

/* ef_test */
extern void test_filter(char *filename);

/* ef_syntax && ef_grammar */
extern int yyerror(char *);                                                                         
extern int yylex(void);

/* ef_tables */
extern void load_tables(void);
extern void load_constants(void);
extern int get_virtualpointer(char *name, char *offname, u_int8 *level, u_int16 *offset, u_int8 *size);
extern int get_constant(char *name, u_int32 *value);

#include <ec_filter.h>

/* ef_encode */
extern int encode_offset(char *string, struct filter_op *fop);
extern int encode_function(char *string, struct filter_op *fop);
extern int encode_const(char *string, struct filter_op *fop);

/* ef_output */

extern int write_output(void);

/* ef_compiler */

struct block {
   union {
      struct instruction *ins;
      struct ifblock *ifb;
   } un;
   u_int16 n;
   u_int8 type;
   struct block *next;
};

struct instruction {
   struct filter_op fop;
};

struct ifblock {
   struct conditions *conds;
   struct block *blk;
   struct block *elseblk;
};

struct conditions {
   u_int16 operator;
   u_int16 n;
   struct filter_op fop;
   struct conditions *next;
};

extern int compiler_set_init(struct block *blk);
extern struct filter_op * compile_tree(void);
extern struct block * compiler_add_block(struct instruction *ins, struct block *blk);
extern struct instruction * compiler_create_instruction(struct filter_op *fop);

#endif

/* EOF */

// vim:ts=3:expandtab

