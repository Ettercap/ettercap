
#ifndef EC_FILTER_H
#define EC_FILTER_H

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
 *    jump(address)
 */

#define MAX_FILTER_LEN  200

struct filter {
   char opcode;
      #define FOP_FUNC  0
      #define FOP_TEST  1
      #define FOP_JMP   2
      #define FOP_DROP  3

   struct function {
      char opcode;
         #define FFUNC_SEARCH    0
         #define FFUNC_REPLACE   1
         #define FFUNC_LOG       2
      char value[MAX_FILTER_LEN];
      size_t value_len;
      char value2[MAX_FILTER_LEN];
      size_t value2_len;
   };

   struct compare {
      u_int16 offset;
      u_int32 value;
   };

   u_int16 goto_if_true;
   u_int16 goto_if_false;
   
};


#endif

/* EOF */

// vim:ts=3:expandtab

