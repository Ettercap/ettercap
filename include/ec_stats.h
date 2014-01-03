#ifndef EC_STATS_H
#define EC_STATS_H

#include<pcap.h>

/*
 * this struct contains all field to collect 
 * statistics about packet and byte rate
 * for the bottom and top half
 */

struct half_stats {
   unsigned long long int pck_recv;
   unsigned long long int pck_size;
   struct timeval ttot;
   struct timeval tpar;
   struct timeval ts;
   struct timeval te;
   unsigned long long int tmp_size;
   unsigned long rate_adv;
   unsigned long rate_worst;
   unsigned long thru_adv;
   unsigned long thru_worst;
};

/* 
 * global statistics: bottom and top half + queue
 */

struct gbl_stats {
   unsigned long long int ps_recv;
   unsigned long long int ps_recv_delta;
   unsigned long long int ps_drop;
   unsigned long long int ps_drop_delta;
   unsigned long long int ps_ifdrop;
   unsigned long long int ps_sent;
   unsigned long long int ps_sent_delta;
   unsigned long long int bs_sent;
   unsigned long long int bs_sent_delta;
   struct half_stats bh;
   struct half_stats th;
   unsigned long queue_max;
   unsigned long queue_curr;
};

#define time_sub(a, b, result) do {                  \
   (result)->tv_sec = (a)->tv_sec - (b)->tv_sec;     \
   (result)->tv_usec = (a)->tv_usec - (b)->tv_usec;  \
   if ((result)->tv_usec < 0) {                      \
      --(result)->tv_sec;                            \
      (result)->tv_usec += 1000000;                  \
   }                                                 \
} while (0)

#define time_add(a, b, result) do {                  \
   (result)->tv_sec = (a)->tv_sec + (b)->tv_sec;     \
   (result)->tv_usec = (a)->tv_usec + (b)->tv_usec;  \
   if ((result)->tv_usec >= 1000000) {               \
      ++(result)->tv_sec;                            \
      (result)->tv_usec -= 1000000;                  \
   }                                                 \
} while (0)


/* exports */

EC_API_EXTERN void stats_wipe(void);
EC_API_EXTERN void stats_update(void);

EC_API_EXTERN unsigned long stats_queue_add(void);
EC_API_EXTERN unsigned long stats_queue_del(void);

EC_API_EXTERN void stats_half_start(struct half_stats *hs);
EC_API_EXTERN void stats_half_end(struct half_stats *hs, bpf_u_int32 len);


#endif

/* EOF */

// vim:ts=3:expandtab

