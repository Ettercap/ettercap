
/* $Id: ec_filter.h,v 1.11 2003/09/19 16:47:47 alor Exp $ */

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
 * we have to implement a struct to contain all the possible
 * operations:
 *
 *    offset == value
 *       e.g.  if (L4.proto == NL_TYPE_TCP)  
 * 
 *    offset = value8
 *    offset = value16
 *    offset = value32
 *       e.g.   L3.ip.ttl = 64
 *              L4.tcp.seq = 0xe77ee77e
 *              DATA.data+32 = 0xff 
 *
 *    search(where, "what")
 *       e.g.  search(DATA.data, "1.99");
 *
 *    replace(where, "what", "value")
 *       e.g.  replace(DATA.data, "1.99", "1.51");
 *
 *    log()
 *
 *    drop()
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
            #define FFUNC_LOG       3
            #define FFUNC_DROP      4
            #define FFUNC_MSG       5
            #define FFUNC_EXEC      6
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
            #define FTEST_LT   1   
            #define FTEST_GT   2
            #define FTEST_LEQ  3
            #define FTEST_GEQ  4
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
};

/* exported functions */

extern int filter_engine(struct filter_op *fop, struct packet_object *po);
extern int filter_load_file(char *filename);
extern void filter_unload(void);

#endif

/* EOF */

// vim:ts=3:expandtab

