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

    $Header: /home/drizzt/dev/sources/ettercap.cvs/ettercap_ng/utils/etterlog/el_display.c,v 1.10 2003/04/06 10:40:11 alor Exp $
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
               color = COL_BLUE;
               break;
         }
         set_color(color);
         fflush(stdout);
      }
      
      /* print it */
      write(fileno(stdout), tmp, ret);
      
      if (GBL.color) {
         reset_color();
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
   struct host_profile *h;
   struct open_port *o;
   struct active_user *u;
   LIST_HEAD(, host_profile) *hosts_list_head = get_host_list_ptr();
   char tmp[MAX_ASCII_ADDR_LEN];
   char os[OS_LEN+1];
   
   /* create the hosts' list */
   create_hosts_list(); 

   /* load the fingerprint database */
   fingerprint_init();

   /* load the manuf database */
   manuf_init();

   fprintf(stdout, "\n\n");

   /* parse the list */
   LIST_FOREACH(h, hosts_list_head, next) {

      memset(os, 0, sizeof(os));
      
      /* XXX respect the TARGET and regex */
      
      /* set the color */
      if (GBL.color) {
         if (h->type & FP_GATEWAY)
            set_color(COL_RED);
         if (h->type & FP_HOST_LOCAL)
            set_color(COL_GREEN);
         if (h->type & FP_HOST_NONLOCAL)
            set_color(COL_BLUE);
      }
      
      fprintf(stdout, "==================================================\n");
      fprintf(stdout, " IP address   : %s \n\n", ip_addr_ntoa(&h->L3_addr, tmp));
      
      if (h->type != FP_HOST_NONLOCAL) {
         fprintf(stdout, " MAC address  : %s \n", mac_addr_ntoa(h->L2_addr, tmp));
         fprintf(stdout, " MANUFACTURER : %s \n\n", manuf_search(h->L2_addr));
      }
      
      fprintf(stdout, " DISTANCE : %d   \n", h->distance);
      if (h->type & FP_GATEWAY)
         fprintf(stdout, " TYPE     : GATEWAY\n\n");
      else if (h->type & FP_HOST_LOCAL)
         fprintf(stdout, " TYPE     : LAN host\n\n");
      else if (h->type & FP_HOST_NONLOCAL)
         fprintf(stdout, " TYPE     : REMOTE host\n\n");
      
      fprintf(stdout, " FINGERPRINT      : %s\n", h->fingerprint);
      if (fingerprint_search(h->fingerprint, os) == ESUCCESS)
         fprintf(stdout, " OPERATING SYSTEM : %s \n\n", os);
      else {
         fprintf(stdout, " OPERATING SYSTEM : unknown fingerprint (please submit it) \n");
         fprintf(stdout, " NEAREST ONE IS   : %s \n\n", os);
      }
         
     
      LIST_FOREACH(o, &(h->open_ports_head), next) {
         
         fprintf(stdout, "   PORT     : %s %d \n", (o->L4_proto == NL_TYPE_TCP) ? "TCP" : "UDP" , ntohs(o->L4_addr));
         fprintf(stdout, "   BANNER   : %s\n", o->banner);
         
         LIST_FOREACH(u, &(o->users_list_head), next) {
            
            fprintf(stdout, "      USER     : %s\n", u->user);
            fprintf(stdout, "      PASS     : %s\n", u->pass);
            fprintf(stdout, "      INFO     : %s\n", u->info);
         }
      }
      
      fprintf(stdout, "\n==================================================\n\n");
      
      /* reset the color */
      if (GBL.color)
         reset_color();
   }
   
   fprintf(stdout, "\n\n");

}

/* EOF */

// vim:ts=3:expandtab

