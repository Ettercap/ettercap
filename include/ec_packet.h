
#if !defined(EC_PACKET_H)
#define EC_PACKET_H

#include <ec_proto.h>
#include <ec_profiles.h>
#include <ec_fingerprint.h>
#include <ec_inet.h>

struct packet_object {
   
   struct L2 {
      u_int16 proto;
      u_char * header;
      size_t len;
      u_char src[ETH_ADDR_LEN];
      u_char dst[ETH_ADDR_LEN];
   } L2;
   
   struct L3 {
      u_short proto;
      u_char * header;
      u_char * options;
      size_t len;
      size_t optlen;
      struct ip_addr src;
      struct ip_addr dst;
      u_int8 ttl;
   } L3;
   
   struct L4 {
      u_char proto;
      u_char * header;
      u_char * options;
      size_t len;
      size_t optlen;
      u_int16 src;
      u_int16 dst;
   } L4;
   
   struct data {
      u_char * data;
      size_t len;
   } DATA;

   size_t fwd_len;         /* lenght of the packet to be forwarded */
   u_char * fwd_packet;    /* the pointer to the buffer to be forwarded */
   
   size_t len;             /* total lenght of the packet */
   u_char * packet;        /* the buffer containing the real packet */

   u_int8 flags;                       /* flags relative to the packet */
      #define PO_IGNORE       ((u_int8)(1))      /* this packet should not be processed (e.g. sniffing filter didn't match it) */
      #define PO_OUTGOING     ((u_int8)(1<<1))   /* this is outgoing and should not be forwarded again */
      #define PO_PCKHOST      ((u_int8)(1<<2))   /* the packet is directed to us */
      
      #define PO_FROMIFACE    ((u_int8)(1<<5))   /* this packet comes from the primary interface */
      #define PO_FROMBRIDGE   ((u_int8)(1<<6))   /* this packet comes form the bridged interface */
      
      #define PO_MOD_CHECK    ((u_int8)(1<<7))   /* it needs checksum recalculation before forwarding */
      #define PO_MOD_LEN      ((u_int8)(1<<8)|PO_MOD_CHECK)   /* it was modified also in its lenght */
  
   int delta;  /* for modified packet this is the delta for the lenght */
   
   /* buffer containing the data to be displayed.
    * some dissector decripts the traffic, but the packet must be forwarded as
    * is, so the decripted data must be placed in a different buffer. 
    * this is that bufffer.
    */
   size_t disp_len;
   char * disp_data;

   /* 
    * here are stored the user and pass collected by dissectors 
    * the "char *" are malloc(ed) by dissectors
    */
   struct dissector_info INFO;
  
   /* the struct for passive identification */
   struct passive_info PASSIVE;
   
};

extern int packet_create_object(struct packet_object **po, u_char * buf, size_t len);
extern int packet_disp_data(struct packet_object *po, u_char *buf, size_t len);
extern int packet_destroy_object(struct packet_object **po);
extern int packet_duplicate(struct packet_object *po, char level, u_char **buf);
#define LEVEL_2      0           /* 00000000 */
#define LEVEL_3      1           /* 00000001 */ 
#define LEVEL_4      (1 << 1)    /* 00000010 */ 
#define LEVEL_DATA   (1 << 2)    /* 00000100 */ 
#define LEVEL_MASK   0x7         /* 00000111 */
#define DUP_COPY     (1 << 3)    /* 00001000 */ 
#define DUP_ALLOC    (1 << 4)    /* 00010000 */

extern void packet_print(struct packet_object *po);

#endif

/* EOF */

// vim:ts=3:expandtab

