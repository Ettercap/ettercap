
/* $Id: ef_functions.h,v 1.17 2004/02/16 21:15:32 alor Exp $ */

#ifndef EF_FUNCTIONS_H
#define EF_FUNCTIONS_H

#include <ec_filter.h>

#define SCRIPT_ERROR(x, ...) FATAL_ERROR("\n[%s:%d]: "x, GBL_OPTIONS.source_file, GBL.lineno, ## __VA_ARGS__ );

#define WARNING(x) do {                   \
if (!GBL_OPTIONS.suppress_warnings)       \
   FATAL_ERROR("\n[%s:%d]: WARINING "x, GBL_OPTIONS.source_file, GBL.lineno);  \
else                                      \
   fprintf(stderr, "\n[%s:%d]: WARINING "x, GBL_OPTIONS.source_file, GBL.lineno);  \
} while(0)

/* ef_main */
extern void ef_debug(u_char level, const char *message, ...);

/* ef_parser */
extern void parse_options(int argc, char **argv);

/* ef_test */
extern void test_filter(char *filename);
extern void print_fop(struct filter_op *fop, u_int32 eip);

/* ef_syntax && ef_grammar */
extern int yyerror(char *);                                                                         
extern int yylex(void);

/* ef_tables */
extern void load_tables(void);
extern void load_constants(void);
extern int get_virtualpointer(char *name, char *offname, u_int8 *level, u_int16 *offset, u_int8 *size);
extern int get_constant(char *name, u_int32 *value);

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
   struct block *next;
   u_int8 type;
      #define BLK_INSTR 0
      #define BLK_IFBLK 1
};

struct instruction {
   struct filter_op fop;
};

struct ifblock {
   struct condition *conds;
   struct block *blk;
   struct block *elseblk;
};

struct condition {
   struct filter_op fop;
   struct condition *next;
   u_int16 op;
      #define COND_AND  0
      #define COND_OR  1
};

extern int compiler_set_root(struct block *blk);
extern size_t compile_tree(struct filter_op **fop);
extern struct block * compiler_add_instr(struct instruction *ins, struct block *blk);
extern struct block * compiler_add_ifblk(struct ifblock *ifb, struct block *blk);
extern struct instruction * compiler_create_instruction(struct filter_op *fop);
extern struct condition * compiler_create_condition(struct filter_op *fop);
extern struct condition * compiler_concat_conditions(struct condition *a, u_int16 op, struct condition *b);
extern struct ifblock * compiler_create_ifblock(struct condition *conds, struct block *blk);
extern struct ifblock * compiler_create_ifelseblock(struct condition *conds, struct block *blk, struct block *elseblk);

#endif

/* EOF */

// vim:ts=3:expandtab

