
#ifndef EC_LOG_H
#define EC_LOG_H

#include <ec_inet.h>
#include <ec_packet.h>

#include <sys/time.h>

/*******************************************
 * NOTE:  all the int variable are stored  *
 *        in network order in the logfile  *
 *                                         *
 * NOTE:  log files are compressed with    *
 *        the deflate algorithm            *
 *******************************************/

/*
 * at the beginning of the file there 
 * are the global information
 */

struct log_global_header {
   /* a magic number for file identification */
   u_short magic;
#define LOG_MAGIC 0xe77e
   /* 
    * offset to the first header in the log file 
    * this assure that we can change this header 
    * and the etterlog parser will be able to 
    * parse also files created by older version
    */
   u_short first_header;
   /* ettercap version */
   char version[10];
   /* creation time of the log */
   struct timeval tv;
   /* the type of the log (packet or info) */
   u_int32 type;
};


/* 
 * every packet in the log file has this format:
 * [header][data][header][data]...
 */

/* this is for a generic packet */
struct log_header_packet {

   struct timeval tv;
   
   u_int8 L2_src[ETH_ADDR_LEN];
   u_int8 L2_dst[ETH_ADDR_LEN];

   struct ip_addr L3_src;
   struct ip_addr L3_dst;
   
   u_int8 L4_proto;
   u_int16 L4_src;
   u_int16 L4_dst;
   
   u_int32 len;
};


/* this is for host infos */
struct log_header_info {
   struct ip_addr host;
};


extern void set_loglevel(int level, char *filename);
#define LOG_PACKET   1
#define LOG_INFO     0

extern void log_packet(struct packet_object *po);
   

#endif

/* EOF */

// vim:ts=3:expandtab

