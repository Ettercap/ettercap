
/* $Id: ec_filter.h,v 1.15 2003/10/04 14:58:34 alor Exp $ */

#ifndef EC_FILTER_H
#define EC_FILTER_H

#include <ec_packet.h>

/* 
 * this is the struct used by the filtering engine
 * it is the equivalent of a processor's instruction
 *
 * they are organized in an array and evaluated one 
 * at a time. the jump are absolute and the addressing
 * is done by the array position.
 *
 */

#define MAX_FILTER_LEN  200

struct filter_op {
   char opcode;
      #define FOP_EXIT     0
      #define FOP_TEST     1
      #define FOP_ASSIGN   2
      #define FOP_FUNC     3
      #define FOP_JMP      4
      #define FOP_JTRUE    5
      #define FOP_JFALSE   6

   /*
    * the first two filed of the structs (op and level) must
    * overlap the same memory region. it is abused in ef_encode.c
    */
   union {
      /* functions */
      struct {
         char op;
            #define FFUNC_SEARCH    0
            #define FFUNC_REGEX     1
            #define FFUNC_REPLACE   2
            #define FFUNC_INJECT    3
            #define FFUNC_LOG       4
            #define FFUNC_DROP      5
            #define FFUNC_MSG       6
            #define FFUNC_EXEC      7
         u_int8 level; 
         u_int8 value[MAX_FILTER_LEN];
         size_t value_len;
         u_int8 value2[MAX_FILTER_LEN];
         size_t value2_len;
      } func;
      
      /* tests */
      struct {
         u_int8   op;
            #define FTEST_EQ   0
            #define FTEST_NEQ  1
            #define FTEST_LT   2   
            #define FTEST_GT   3
            #define FTEST_LEQ  4
            #define FTEST_GEQ  5
         u_int8   level;
         u_int8   size;
         u_int16  offset;
         u_int32  value;
         char     string[MAX_FILTER_LEN];
         size_t   string_len;
      } test, assign;

      /* jumps */
      u_int16 jmp;
      
   } op;
};

/* the header for a binary filter file */

struct filter_header {
   /* magic number */
   u_int16 magic; 
      #define EC_FILTER_MAGIC 0xe77e
   /* ettercap version */
   char version[10];
   /* pointers to the sections */
   u_int16 data;
   u_int16 code;
};

/* exported functions */

extern int filter_engine(struct filter_op *fop, struct packet_object *po);
extern int filter_load_file(char *filename);
extern void filter_unload(void);

#endif

/* EOF */

// vim:ts=3:expandtab

