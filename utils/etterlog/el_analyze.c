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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterlog/el_analyze.c,v 1.2 2003/03/26 20:38:02 alor Exp $
*/

#include <el.h>
#include <ec_log.h>
#include <el_functions.h>

#include <sys/stat.h>

void analyze(void);

/*******************************************/

void analyze(void)
{
   struct log_global_header hdr;
   struct log_header_packet pck;
   int ret, count = 0;
   int tot_size = 0, pay_size = 0;
   u_char *buf;
   struct stat st;
   
   /* get the global header */
   ret = get_header(&hdr);
   ON_ERROR(ret, -EINVALID, "Invalid log file");
   
   /* read the logfile */
   LOOP {
      ret = get_packet(&pck, &buf);

      /* on error exit the loop */
      if (ret != ESUCCESS)
         break;
      
      count++;
      tot_size += sizeof(struct log_header_packet) + pck.len;
      pay_size += pck.len;
      
      SAFE_FREE(buf);
   }

   /* get the file stat */
   stat(GBL.logfile, &st);
   
   printf("Log file version    : %s\n", hdr.version);
   printf("Timestamp           : %s", ctime((time_t *)&hdr.tv.tv_sec));
   printf("Type                : %s\n\n", (hdr.type == LOG_PACKET) ? "LOG_PACKET" : "LOG_INFO" );

   printf("Log file size (compressed)   : %d\n", (int)st.st_size);   
   printf("Log file size (uncompressed) : %d\n", tot_size);
   printf("Effective payload size       : %d\n", pay_size);
   printf("Wasted percentage            : %.2f %%\n\n", 100 - ((float)pay_size * 100 / (float)tot_size) );
   
   printf("Number of packets            : %d\n", count);
   if(count == 0) exit(0);

   printf("Average size per packet      : %d\n", pay_size / count );
   printf("\n");
   
   exit(0);
}

/* EOF */

// vim:ts=3:expandtab

