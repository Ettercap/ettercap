/*
    etterlog -- display packets or infos

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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterlog/el_display.c,v 1.7 2003/04/05 09:25:10 alor Exp $
*/

#include <el.h>
#include <ec_log.h>
#include <ec_format.h>
#include <ec_fingerprint.h>
#include <ec_manuf.h>
#include <el_functions.h>

#include <sys/stat.h>
#include <regex.h>

/* proto */

void display(void);
static void display_packet(void);
static void display_info(void);
static void display_headers(struct log_header_packet *pck);
void set_display_regex(char *regex);

/*******************************************/

void display(void)
{
   switch(GBL.hdr.type) {
      case LOG_PACKET:
         display_packet();
         break;
      case LOG_INFO:
         display_info();
         break;
   }
}


/* display a packet log file */

static void display_packet(void)
{
   struct log_header_packet pck;
   int ret;
   u_char *buf;
   u_char *tmp;
   int versus;
   
   /* read the logfile */
   LOOP {
      ret = get_packet(&pck, &buf);

      /* on error exit the loop */
      if (ret != ESUCCESS)
         break;

      /* the packet should complain to the target specifications */
      if (!is_target_pck(&pck)) {
         SAFE_FREE(buf);
         continue;
      }
      
      /* the packet should complain to the connection specifications */
      if (!is_conn(&pck, &versus)) {
         SAFE_FREE(buf);
         continue;
      }
     
      /* if the regex does not match, the packet is not interesting */
      if (GBL.regex && regexec(GBL.regex, buf, 0, NULL, 0) != 0) {
         SAFE_FREE(buf);
         continue;
      }
                  
      /* 
       * prepare the buffer,
       * the max length is hex_fomat
       * so use its length for the buffer
       */
      tmp = calloc(hex_len(pck.len), sizeof(u_char));
      ON_ERROR(tmp, NULL, "can't allocate memory");

      /* display the headers only if necessary */
      if (!GBL.no_headers)
         display_headers(&pck);
      
      /* 
       * format the packet with the function
       * set by the user
       */
      ret = GBL.format(buf, pck.len, tmp);
     
      /* the ANSI escape for the color */
      if (GBL.color) {
         int color = 0;
         switch (versus) {
            case VERSUS_SOURCE:
               color = COL_GREEN;
               break;
            case VERSUS_DEST:
               color = COL_BLU;
               break;
         }
         fprintf(stdout, "\033[%dm", color);
         fflush(stdout);
      }
      
      /* print it */
      write(fileno(stdout), tmp, ret);
      
      if (GBL.color) {
         fprintf(stdout, "\033[0m");
         fflush(stdout);
      }
      
      SAFE_FREE(buf);
      SAFE_FREE(tmp);
   }

   if (!GBL.no_headers)
      fprintf(stdout, "\n\n");
   
   return;
}

/*
 * display the packet headers 
 */

static void display_headers(struct log_header_packet *pck)
{
   /* it is at least 26... rounding up */
   char time[28];
   char tmp1[MAX_ASCII_ADDR_LEN];
   char tmp2[MAX_ASCII_ADDR_LEN];
   char flags[8];
   char *p = flags;
   char proto[5];
   
   memset(flags, 0, sizeof(flags));
   
   fprintf(stdout, "\n\n");
   
   /* remove the final '\n' */
   strcpy(time, ctime((time_t *)&pck->tv.tv_sec));
   time[strlen(time)-1] = 0;
   
   /* displat the date */
   fprintf(stdout, "%s [%u]\n", time, (u_int32)pck->tv.tv_usec);
  
   if (GBL.showmac) {
      /* display the mac addresses */
      mac_addr_ntoa(pck->L2_src, tmp1);
      mac_addr_ntoa(pck->L2_dst, tmp2);
      fprintf(stdout, "%17s --> %17s\n", tmp1, tmp2 );
   }
  
   /* calculate the flags */
   if (pck->L4_flags & TH_SYN) *p++ = 'S';
   if (pck->L4_flags & TH_FIN) *p++ = 'F';
   if (pck->L4_flags & TH_RST) *p++ = 'R';
   if (pck->L4_flags & TH_ACK) *p++ = 'A';
   if (pck->L4_flags & TH_PSH) *p++ = 'P';
  
   /* determine the proto */
   switch(pck->L4_proto) {
      case NL_TYPE_TCP:
         strcpy(proto, "TCP");
         break;
      case NL_TYPE_UDP:
         strcpy(proto, "UDP");
         break;
   }
   
   /* display the ip addresses */
   ip_addr_ntoa(&pck->L3_src, tmp1);
   ip_addr_ntoa(&pck->L3_dst, tmp2);
   fprintf(stdout, "%s  %s:%d --> %s:%d | %s\n", proto, tmp1, ntohs(pck->L4_src), 
                                                        tmp2, ntohs(pck->L4_dst),
                                                        flags);

   fprintf(stdout, "\n");
}

/*
 * compile the regex
 */

void set_display_regex(char *regex)
{
   int err;
   char errbuf[100];

   /* allocate the new structure */
   GBL.regex = calloc(1, sizeof(regex_t));
   ON_ERROR(GBL.regex, NULL, "can't allocate memory");

   err = regcomp(GBL.regex, regex, REG_EXTENDED | REG_NOSUB );

   if (err) {
      regerror(err, GBL.regex, errbuf, sizeof(errbuf));
      FATAL_ERROR("%s\n", errbuf);
   }                      
}

/* display an inf log file */

static void display_info(void)
{

   /* create the host list */
   create_hosts_list();

   /* load the fingerprint database */
   fingerprint_init();

   /* load the manuf database */
   manuf_init();


   NOT_IMPLEMENTED();

#if 0
   struct log_header_info pck;
   int ret;
   u_char *buf;
   int versus;
   
   /* read the logfile */
   LOOP {
      ret = get_info(&pck, &buf);

      /* on error exit the loop */
      if (ret != ESUCCESS)
         break;

      /* the packet should complain to the target specifications */
      if (!is_target_info(&pck)) {
         SAFE_FREE(buf);
         continue;
      }
      
      /* if the regex does not match, the packet is not interesting */
      
      SAFE_FREE(buf);
   }

   fprintf(stdout, "\n\n");
#endif
   NOT_IMPLEMENTED();
}

/* EOF */

// vim:ts=3:expandtab

