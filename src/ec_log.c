/*
    ettercap -- log handling module

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

    $Id: ec_log.c,v 1.7 2003/03/31 21:46:49 alor Exp $
*/

#include <ec.h>
#include <ec_log.h>
#include <ec_packet.h>
#include <ec_passive.h>
#include <ec_threads.h>
#include <ec_hook.h>

#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <zlib.h>
#include <regex.h>

/* globals */

static gzFile fd_cp;
static gzFile fd_ci;
static int fd_p;
static int fd_i;

static regex_t *log_regex;

/* protos */

static void log_close(void);
int set_logregex(char *regex);
void set_loglevel(int level, char *filename);

void log_packet(struct packet_object *po);

void log_write_info(struct packet_object *po);
static int log_write_header(int type);
static void log_write_packet(struct packet_object *po);

static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
#define LOG_LOCK     do{ pthread_mutex_lock(&log_mutex); } while(0)
#define LOG_UNLOCK   do{ pthread_mutex_unlock(&log_mutex); } while(0)

/************************************************/

/* 
 * this function is executed at high privs.
 * open the file descriptor for later use
 * and set the log level
 * LOG_PACKET = packet + info
 * LOG_INFO = only info
 */

void set_loglevel(int level, char *filename)
{
   char eci[strlen(filename)+5];
   char ecp[strlen(filename)+5];
   int zerr;
   
   DEBUG_MSG("set_loglevel(%d,%s)", level, filename); 

   sprintf(eci, "%s.eci", filename);
   sprintf(ecp, "%s.ecp", filename);
   
   /* open the file(s) */
   switch(level) {
      case LOG_PACKET:
         if (GBL_OPTIONS->compress) {
            fd_cp = gzopen(ecp, "wb9");
            ON_ERROR(fd_cp, NULL, "%s", gzerror(fd_cp, &zerr));
         } else {
            fd_p = open(ecp, O_CREAT | O_TRUNC | O_RDWR);
            ON_ERROR(fd_p, -1, "Can't create %s", ecp);
         }

         /* set the permissions */
         chmod(ecp, 0600);
         
         /* initialize the log file */
         log_write_header(LOG_PACKET);
         
         /* add the hook point to DISPATCHER */
         hook_add(HOOK_DISPATCHER, &log_packet);

         /* no break here, loglevel is incremental */
         
      case LOG_INFO:
         if (GBL_OPTIONS->compress) {
            fd_ci = gzopen(eci, "wb9");
            ON_ERROR(fd_ci, NULL, "%s", gzerror(fd_ci, &zerr));
         } else {
            fd_i = open(eci, O_CREAT | O_TRUNC | O_RDWR);
            ON_ERROR(fd_i, -1, "Can't create %s", eci);
         }
         
         /* set the permissions */
         chmod(eci, 0600);
         
         /* initialize the log file */
         log_write_header(LOG_INFO);

         /* XXX -- add other hook for ICMP, ARP and so on.. */
         
         /* add the hook point to DISPATCHER */
         hook_add(HOOK_DISPATCHER, &log_write_info);
         
         break;
   }

   atexit(&log_close);
}

/* close the log files */
void log_close(void)
{
   DEBUG_MSG("ATEXIT: log_close");

   if (fd_cp) gzclose(fd_cp);
   if (fd_ci) gzclose(fd_ci);

   if (fd_p) close(fd_p);
   if (fd_i) close(fd_i);
   
}

/*
 * initialize the log file with 
 * the propre header
 */

static int log_write_header(int type)
{
   gzFile fdc = 0;
   int fd = 0;
   struct log_global_header lh;
   int c, zerr;
   
   DEBUG_MSG("log_write_header : type %d", type);

   memset(&lh, 0, sizeof(struct log_global_header));

   /* the magic number */
   lh.magic = htons(LOG_MAGIC);
   
   /* the offset of the first header is equal to the size of this header */
   lh.first_header = htons(sizeof(struct log_global_header));
   
   strlcpy(lh.version, GBL_VERSION, sizeof(lh.version));
   
   /* creation time of the file */
   gettimeofday(&lh.tv, 0);
   lh.tv.tv_sec = htonl(lh.tv.tv_sec);
   lh.tv.tv_usec = htonl(lh.tv.tv_usec);
      
   lh.type = htonl(type);

   switch(type) {
      case LOG_PACKET:
         fdc = fd_cp;
         fd = fd_p;
         break;
      case LOG_INFO:
         fdc = fd_ci;
         fd = fd_i;
         break;
   }

   LOG_LOCK;
   
   if (GBL_OPTIONS->compress) {
      c = gzwrite(fdc, &lh, sizeof(lh));
      ON_ERROR(c, -1, "%s", gzerror(fdc, &zerr));
   } else {
      c = write(fd, &lh, sizeof(lh));
      ON_ERROR(c, -1, "Can't write to logfile");
   }

   LOG_UNLOCK;
   
   return c;
}



/* log all the packet to the logfile */

void log_write_packet(struct packet_object *po)
{
   struct log_header_packet hp;
   int c, zerr;

   memset(&hp, 0, sizeof(struct log_header_packet));
   
   /* adjust the timestamp */
   memcpy(&hp.tv, &po->ts, sizeof(struct timeval));
   hp.tv.tv_sec = htonl(hp.tv.tv_sec);
   hp.tv.tv_usec = htonl(hp.tv.tv_usec);
  
   memcpy(&hp.L2_src, &po->L2.src, ETH_ADDR_LEN);
   memcpy(&hp.L2_dst, &po->L2.dst, ETH_ADDR_LEN);
   
   memcpy(&hp.L3_src, &po->L3.src, sizeof(struct ip_addr));
   memcpy(&hp.L3_dst, &po->L3.dst, sizeof(struct ip_addr));
  
   hp.L4_flags = po->L4.flags;
   hp.L4_proto = po->L4.proto;
   hp.L4_src = po->L4.src;
   hp.L4_dst = po->L4.dst;
   
   hp.len = htonl(po->disp_len);

   LOG_LOCK;
   
   if (GBL_OPTIONS->compress) {
      c = gzwrite(fd_cp, &hp, sizeof(hp));
      ON_ERROR(c, -1, "%s", gzerror(fd_cp, &zerr));

      c = gzwrite(fd_cp, po->disp_data, po->disp_len);
      ON_ERROR(c, -1, "%s", gzerror(fd_cp, &zerr));
   } else {
      c = write(fd_p, &hp, sizeof(hp));
      ON_ERROR(c, -1, "Can't write to logfile");

      c = write(fd_p, po->disp_data, po->disp_len);
      ON_ERROR(c, -1, "Can't write to logfile");
   }
   
   LOG_UNLOCK;
}

/*
 * compile the regex
 */

int set_logregex(char *regex)
{
   int err;
   char errbuf[100];
   
   DEBUG_MSG("set_logregex: %s", regex);

   /* free any previous compilation */
   SAFE_FREE(log_regex);
  
   /* allocate the new structure */
   log_regex = calloc(1, sizeof(regex_t));
   ON_ERROR(log_regex, NULL, "can't allocate memory");

   err = regcomp(log_regex, regex, REG_EXTENDED | REG_NOSUB );

   if (err) {
      regerror(err, log_regex, errbuf, sizeof(errbuf));
      SAFE_FREE(log_regex);
      FATAL_MSG("%s\n", errbuf);
   }

   return ESUCCESS;
}

/* 
 * function registered to HOOK_DISPATCHER
 * check the regex (if present) and log packets
 */

void log_packet(struct packet_object *po)
{
   /* the regex is set, respect it */
   if (log_regex) {
      if (regexec(log_regex, po->DATA.data, 0, NULL, 0) == 0)
         log_write_packet(po);
   } else {
      /* if no regex is set, dump all the packets */
      log_write_packet(po);
   }
   
}

/*
 * log passive infomations
 */

void log_write_info(struct packet_object *po)
{
   struct log_header_info hi;
   int c, zerr;

   memset(&hi, 0, sizeof(struct log_header_info));

   /* the mac address */
   memcpy(&hi.L2_addr, &po->L2.src, ETH_ADDR_LEN);
   
   /* the ip address */
   memcpy(&hi.L3_addr, &po->L3.src, sizeof(struct ip_addr));
  
   hi.L4_proto = po->L4.proto;

   if (is_open_port(po))
      /* the port is at high probability open, log it */
      hi.L4_addr = po->L4.src;
   else
      /* the port is not open */
      hi.L4_addr = 0;
  
   /* 
    * distance in hop :
    *
    * the distance is calculated as the difference between the
    * predicted initial ttl number and the current ttl value.
    */
   hi.distance = TTL_PREDICTOR(po->L3.ttl) - po->L3.ttl + 1;
   /* our machine is at distance 0 (special case) */
   if (ip_addr_cmp(&po->L3.src, &GBL_IFACE->ip))
      hi.distance = 0;

   /* OS identification */
   memcpy(&hi.finger, po->PASSIVE.fingerprint, FINGER_LEN);
   
   /* service banner */
   memcpy(&hi.banner, po->PASSIVE.banner, BANNER_LEN);
   
   /* local, non local, gateway ecc ecc */
   hi.type = po->PASSIVE.flags;

   LOG_LOCK;
   
   if (GBL_OPTIONS->compress) {
      c = gzwrite(fd_ci, &hi, sizeof(hi));
      ON_ERROR(c, -1, "%s", gzerror(fd_cp, &zerr));
   } else {
      c = write(fd_i, &hi, sizeof(hi));
      ON_ERROR(c, -1, "Can't write to logfile");
   }
   
   LOG_UNLOCK;
}


/* EOF */

// vim:ts=3:expandtab

