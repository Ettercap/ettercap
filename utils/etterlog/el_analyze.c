/*
    etterlog -- analysis module

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterlog/el_analyze.c,v 1.7 2003/04/03 15:10:46 alor Exp $
*/

#include <el.h>
#include <ec_log.h>
#include <ec_profiles.h>
#include <el_functions.h>

#include <sys/stat.h>

void analyze(void);
void analyze_packet(void);
void analyze_info(void);

void create_hosts_list(void);

/*******************************************/

void analyze(void)
{
   switch(GBL.hdr.type) {
      case LOG_PACKET:
         analyze_packet();
         break;
      case LOG_INFO:
         analyze_info();
         break;
   }
}


/* analyze a packet log file */

void analyze_packet(void)
{
   struct log_header_packet pck;
   int ret, count = 0;
   int tot_size = 0, pay_size = 0;
   u_char *buf;
   struct stat st;
   
   fprintf(stdout, "\nAnalyzing the log file (one dot for 100 packets)\n");
 
   tot_size = sizeof(struct log_global_header);
   
   /* read the logfile */
   LOOP {
      
      memset(&pck, 0, sizeof(struct log_header_packet));
      
      ret = get_packet(&pck, &buf);

      /* on error exit the loop */
      if (ret != ESUCCESS)
         break;
      
      count++;
      tot_size += sizeof(struct log_header_packet) + pck.len;
      pay_size += pck.len;
    
      if (count % 100 == 0) {
         fprintf(stderr, ".");
         fflush(stderr);
      }
      
      SAFE_FREE(buf);
   }

   /* get the file stat */
   stat(GBL.logfile, &st);
   
   fprintf(stdout, "\n\n");
   fprintf(stdout, "Log file size (compressed)   : %d\n", (int)st.st_size);   
   fprintf(stdout, "Log file size (uncompressed) : %d\n", tot_size);
   if (tot_size != 0)
      fprintf(stdout, "Compression ratio            : %.2f %%\n\n", 100 - ((float)st.st_size * 100 / (float)tot_size) );
   fprintf(stdout, "Effective payload size       : %d\n", pay_size);
   if (tot_size != 0)
      fprintf(stdout, "Wasted percentage            : %.2f %%\n\n", 100 - ((float)pay_size * 100 / (float)tot_size) );
   
   fprintf(stdout, "Number of packets            : %d\n", count);
   if (count != 0)
      fprintf(stdout, "Average size per packet      : %d\n", pay_size / count );
   fprintf(stdout, "\n");
   
   return;
}

/* analyze an info log file */

void analyze_info(void)
{
   /* create the hosts' list */
   create_hosts_list(); 
   
   NOT_IMPLEMENTED();
}


void create_hosts_list(void)
{
   struct log_header_info inf;
   int ret;
   struct dissector_info buf;
   
   /* read the logfile */
   LOOP {

      memset(&inf, 0, sizeof(struct log_header_info));
      memset(&buf, 0, sizeof(struct dissector_info));
      
      ret = get_info(&inf, &buf);

      /* on error exit the loop */
      if (ret != ESUCCESS)
         break;
      
      printf("create_hosts_list: finger %s\n\n", inf.fingerprint);
      
      printf("create_hosts_list: user %s\n", buf.user); 
      printf("create_hosts_list: pass %s\n", buf.pass); 
      printf("create_hosts_list: info %s\n", buf.info); 
      printf("create_hosts_list: banner %s\n\n", buf.banner); 
   }

}

/* EOF */

// vim:ts=3:expandtab

