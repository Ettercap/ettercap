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

    $Id: ec_log.c,v 1.3 2003/03/26 20:38:00 alor Exp $
*/

#include <ec.h>
#include <ec_log.h>
#include <ec_packet.h>
#include <ec_hook.h>

#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>

#include <zlib.h>

/* globals */

static gzFile fd_ecp;
static gzFile fd_eci;

/* protos */

void set_loglevel(int level, char *filename);
void log_packet(struct packet_object *po);
void log_close(void);

static int log_write_header(gzFile fd, int type);

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
   
   DEBUG_MSG("set_loglevel(%d,%s)", level, filename); 

   sprintf(eci, "%s.eci", filename);
   sprintf(ecp, "%s.ecp", filename);
   
   /* open the file(s) */
   switch(level) {
      case LOG_PACKET:
         fd_ecp = gzopen(ecp, "wb9");
         ON_ERROR(fd_ecp, NULL, "Can't create %s", ecp);

         /* set the permissions */
         chmod(ecp, 0600);
         
         /* initialize the log file */
         log_write_header(fd_ecp, LOG_PACKET);
         
         /* add the hook point to DISPATCHER */
         hook_add(HOOK_DISPATCHER, &log_packet);
         /* no break here, loglevel is incremental */
         
      case LOG_INFO:
         fd_eci = gzopen(eci, "wb9");
         ON_ERROR(fd_eci, NULL, "Can't create %s", eci);
         
         /* set the permissions */
         chmod(eci, 0600);
         
         /* initialize the log file */
         log_write_header(fd_eci, LOG_INFO);

         /* XXX - implement the info hook */
         
         break;
   }

   atexit(&log_close);
}

/* close the log files */
void log_close(void)
{
   DEBUG_MSG("ATEXIT: log_close");

   if (fd_ecp) 
      gzclose(fd_ecp);
   
   if (fd_eci) 
      gzclose(fd_eci);
}

/*
 * initialize the log file with 
 * the propre header
 */

static int log_write_header(gzFile fd, int type)
{
   struct log_global_header lh;
   int c;
   
   DEBUG_MSG("log_write_header : type %d", type);

   memset(&lh, 0, sizeof(lh));

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

   c = gzwrite(fd, &lh, sizeof(lh));
   ON_ERROR(c, -1, "Can't write to the logfile");
         
   return c;
}



/* log all the packet to the logfile */

void log_packet(struct packet_object *po)
{
   struct log_header_packet hp;
   int c;

   /* adjust the timestamp */
   memcpy(&hp.tv, &po->ts, sizeof(struct timeval));
   hp.tv.tv_sec = htonl(hp.tv.tv_sec);
   hp.tv.tv_usec = htonl(hp.tv.tv_usec);
  
   memcpy(&hp.L2_src, &po->L2.src, ETH_ADDR_LEN);
   memcpy(&hp.L2_dst, &po->L2.dst, ETH_ADDR_LEN);
   
   memcpy(&hp.L3_src, &po->L3.src, sizeof(struct ip_addr));
   memcpy(&hp.L3_dst, &po->L4.dst, sizeof(struct ip_addr));
  
   hp.L4_proto = po->L4.proto;
   hp.L4_src = po->L4.src;
   hp.L4_dst = po->L4.dst;
   
   hp.len = htonl(po->disp_len);

   c = gzwrite(fd_ecp, &hp, sizeof(hp));
   ON_ERROR(c, -1, "Can't write to the logfile");

   c = gzwrite(fd_ecp, po->disp_data, po->disp_len);
   ON_ERROR(c, -1, "Can't write to the logfile");
   
}


/* EOF */

// vim:ts=3:expandtab

